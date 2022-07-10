from django.shortcuts import render
from django.db import connection, connections, utils
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.shortcuts import redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from django.middleware import csrf
from django.template.defaultfilters import filesizeformat
from django.utils.translation import ugettext_lazy as _
from django.dispatch import receiver
from django.db.models.signals import post_save
from . models import *
from . import api_temp
#from django import forms
from pydebugger.debug import debug
import datetime
import os
import sys
#  if __name__ == '__main__':
    #  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vis_p.settings')
#  else:
    #  try:
        #  from .models import VIS_UserLogin, VisSessions, VisLogs as vlogs, ItemmasterdataVis
    #  except ImportError:
        #  pass

#  try:
    #  from . encrypt import Crypt as crypt
#  except:
    #  from encrypt import Crypt as crypt

#  import sys
from django.template import RequestContext
#  from full_url.grabber import RequestGrabber
import re
if sys.version_info.major == 3:
    import hashlib
    class md5():

        @classmethod
        def new(self, data):
            if not isinstance(data, bytes):
                return hashlib.md5(bytes(data, encoding='utf-8'))
            else:
                return hashlib.md5(data)
else:
    import md5
#  import httpagentparser
#  if __name__ == '__main__':
    #  import views
#  else:
    #  try:
        #  from vis import views
    #  except:
        #  pass
import traceback
#  from decimal import Decimal
import json
import ast
import pytz
#  from xnotify import notify
#  import re
#  from rest_framework.authtoken.models import Token
#  import redis
#  rds = redis.Redis(host='localhost', port=6379, db=0)
#  from . forms import EditUserForm
#  try:
    #  from . terbilang import Terbilang
#  except:
    #  from terbilang import Terbilang

#  try:
    #  debug(ENCRYPT_KEY = settings.ENCRYPT_KEY, debug = True)
    #  debug(ENCRYPT_KEY = settings.ENCRYPT_KEY_SAVED, debug = True)
#  except:
    #  pass

def handle_page_not_found_404(request, exception):

    #page_title='Page Not Found'
    return render("error.html", {})

def error_db(request):
    return render(request, "database_error.html")
def get_meta(request):
    notify.send("VIS", f"META = {request.META}", "get_meta", "get")
    return HttpResponse("<table><tr><td>" + str(request.META) +  "</td></tr></table>")

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    debug(x_forwarded_for = request.META.items(),  debug = True)
    if x_forwarded_for:
        print("returning FORWARDED_FOR")
        ip = x_forwarded_for.split(',')[-1].strip()
        debug(ip = ip, debug = True)
    elif request.META.get('HTTP_X_REAL_IP'):
        print ("returning REAL_IP")
        ip = request.META.get('HTTP_X_REAL_IP')
        debug(ip1 = ip, debug = True)
    else:
        print ("returning REMOTE_ADDR")
        ip = request.META.get('REMOTE_ADDR')
        debug(ip2 = ip, debug = True)
    return ip

def add_log(request, module = '', message = ''):
    time = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S.%f')
    path = request.get_full_path()
    session_id = request.COOKIES.get("sessionid")
    username = request.session.get("username") or request.COOKIES.get("username")
    ip = get_client_ip(request)
    user_agent = request.META['HTTP_USER_AGENT']
    debug(time = time, debug = True)
    debug(path = path, debug = True)
    debug(session_id = session_id, debug = True)
    debug(username = username, debug = True)
    debug(ip = ip, debug = True)
    debug(user_agent = user_agent, debug = True)
    debug(module = module, debug = True)
    debug(message = message, debug = True)
    a = vlogs(time = time, path = path, session_id = session_id, username = username, ip_address = ip, user_agent = user_agent, module = module, message = message)
    a.save()


def check_connection(request, cursor, sql_script = None):
    MAX_TIMEOUT = settings.MAX_TIMEOUT
    data = {}
    n = 1
    while 1:
        try:
            if sql_script:
                cursor.execute(sql_script)
            data = cursor.fetchall()
            debug(data = data)
            return data
        except utils.Error:
            print("ERROR 1:", utils.Error)
            #return render(request, "database_error.html")

            debug("utils.Error", debug = True)
            #notify.send("VIS", f"check_connection ~ utils.Error", "vis", "warning")
            #notify.send("VIS", f"utils.Error: {get_client_ip(request)}: {traceback.format_exc()}", "vis", "warning")
            #return getattr(views, 'error_db')(request,)
            if n == MAX_TIMEOUT:
                #return getattr(views, 'error_db')(request,)
                break
            else:
                n += 1

        except:
            print("ERROR:", tracebaack.format_exc())
            debug("utils.Error", debug = True)
            #notify.send("VIS", f"check_connection ~ ERROR 2: {get_client_ip(request)}: {traceback.format_exc()}", "vis", "warning")
            #return getattr(views, 'error_db')(request,)
            break
    return data

def index(request):
    '''
        return user info if has login
    '''
    return get_user()
    #return render(request, 'index.html', data)
    # return render_to_response('index.html', data, context_instance=RequestContext(request))


def check_login(api = None, data = {}):
    debug(api = api)
    debug(data = data)
    if not api and not data:
        debug(data = data)
        return data
    if data:
        return data
    try:
        if api:
            with connection.cursor() as cursor:
                cursor.execute("select * from users where api = '{}'".format(api))
                data = cursor.fetchall()
                debug(data = data)
            if not data:
                with connection.cursor() as cursor:
                    cursor.execute("select * from temp_api where api = '{}'".format(api))
                    data = cursor.fetchall()
                    debug(data = data)
    except:
        print("ERROR:", traceback.format_exc())
    return data

def check_login2(api = None, data = {}):
    debug(api = api)
    debug(data = data)
    if not api and not data:
        debug(data = data)
        return data
    if data:
        return data
    try:
        if api:
            with connection.cursor() as cursor:
                cursor.execute("select * from users where api = '{}'".format(api))
                data = cursor.fetchall()
                debug(data = data)
    except:
        print("ERROR:", traceback.format_exc())
    return data

def is_login(api = None, data = None):
    data = data or check_login(api)
    debug(data = data)
    if data:
        if data[0][-3] == '1':
            debug(data_check = data[0][-3])
            return True
    return False

def generate_temp_api(request = None, new = True, api = None):
    #data = list(filter(lambda k: k.expired.second < ((timezone.localtime() + timedelta(seconds=60)).second or (timezone.localtime() - timedelta(hours=1)).second), temp_api.objects.all()))
    #data = list(filter(lambda k: k.expired.timestamp() < (timezone.localtime() + timedelta(seconds=60)).timestamp(), temp_api.objects.all()))
    api = api or request.GET.get('api') or request.POST.get('api')
    if not api:
        data = list(filter(lambda k: (timezone.localtime() + timedelta(seconds=60)).timestamp() - k.expired.timestamp() > 59, temp_api.objects.all()))
        debug(data = data)
        if data:
            for i in data:
                i.delete()
        if new:
            new = api_temp.generator()
            expired = timezone.localtime() + timedelta(seconds=60)
            a = temp_api(api = new, expired=expired)
            a.save()
            if request:
                return JsonResponse({'api_key':new, 'expired': datetime.datetime.strftime(expired, '%Y-%m-%d %H:%M:%S:%f'), 'message': 'use this api for login, after login use a new api_key from result'})
    else:
        if request:
            return get_user(request, api)
        #return JsonResponse({'message': 'please read documentation'})
    return new


def get_user(request = None, api = None, username = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            if request:
                return JsonResponse({"error": "invalid api key", 'status':'error'})
            else:
                return {}
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    username = username or request.POST.get('username') or request.GET.get('username')
    debug(username = username)

    data = check_login2(api)
    debug(data = data)
    if not data:
        if request:
            return JsonResponse({"error": "invalid api key", 'status':'error'})
        return {}

    #data = {'data':''}
    IS_LOGIN = is_login(api, data)
    debug(IS_LOGIN = IS_LOGIN)

    if data:
        debug(username = username)
        debug(api = api)
        with connection.cursor() as cursor:
            cursor.execute("select * from users where name = '{}' or api = '{}'".format(username, api))
            data = check_connection(request, cursor)
            debug(data = data)
            if not data:
                if request:
                    return JsonResponse({"data": {}, 'status':'error', 'error':'no user found !'})
                else:
                    return {}
            data = {
                'username': data[0][2],
                'password': data[0][3],
                'status': data[0][4],
                'islogin': data[0][5],
                'id': data[0][6],
                'api_key': data[0][7],
                'email': data[0][8],
            }
            if request:
                return JsonResponse({"data": data, 'status':'success'})
            else:
                return data

def login(request, api = None, username = None, password = None, logout = False):
    api = api or request.GET.get('api') or request.POST.get('api') or request.session.get('api')
    username = username or request.POST.get('username') or request.GET.get('username')
    password = password or request.POST.get('password') or request.GET.get('password')
    debug(username = username)
    debug(password = password)

    if logout:
        data = check_login2(api)
    else:
        data = check_login(api)
    debug(data = data)
    if not data:
        if logout:
            request.session.clear()
        return JsonResponse({"error": "invalid api key", 'status':'error'})

    #data = {'data':''}
    IS_LOGIN = is_login(api, data)
    debug(IS_LOGIN = IS_LOGIN)

    if data:
        if not IS_LOGIN and username and password:
            debug("process 1")
            with connection.cursor() as cursor:
                if logout:
                    cursor.execute("update users set logged = '0' where name = '{}' and password = '{}'".format(username, password))
                else:
                    cursor.execute("update users set logged = '1' where name = '{}' and password = '{}'".format(username, password))
            debug(username = username)
            debug(password = password)
            with connection.cursor() as cursor:
                cursor.execute("select * from users where name = '{}' and password = '{}'".format(username, password))
                data = check_connection(request, cursor)
                debug(data = data)
            if not data:
                return JsonResponse({"error": "invalid username or password", 'status':'error'})
            data = {
                'username': data[0][2],
                'password': data[0][3],
                'status': data[0][4],
                'islogin': data[0][5],
                'id': data[0][6],
                'api_key': data[0][7],
                'email': data[0][8],
            }
            if not logout:
                request.session.update({
                    'api':data.get('api_key'),
                    'user_id':data.get('id'),
                    'username': data.get('username'),
                    'is_login': data.get('islogin'),
                })
        elif is_login(api, data) and data:
            debug(data = data)
            #status_login = 0
            with connection.cursor() as cursor:
                if logout:
                    if not username and not password and api:
                        if logout:
                            cursor.execute("update users set logged = '0' where api = '{}'".format(api))
                        else:
                            cursor.execute("update users set logged = '1' where api = '{}'".format(api))
                    else:
                        if logout:
                            cursor.execute("update users set logged = '0' where name = '{}' and password = '{}'".format(username, password))
                        else:
                            cursor.execute("update users set logged = '1' where name = '{}' and password = '{}'".format(username, password))
                    #status_login = 0
                else:
                    cursor.execute("update users set logged = '1' where name = '{}' and password = '{}'".format(username, password))
            with connection.cursor() as cursor:
                if api and not username and not password:
                    cursor.execute("select * from users where api = '{}'".format(api))
                elif username and password:
                    cursor.execute("select * from users where name = '{}' and password = '{}'".format(username, password))
                data = check_connection(request, cursor)
            data = {
                'username': data[0][2],
                'password': data[0][3],
                'status': data[0][4],
                'islogin': data[0][5],
                'id': data[0][6],
                'api_key': data[0][7],
                'email': data[0][8],
            }
            debug(data = data)
            if not logout:
                debug(data = data)
                request.session.update({
                    'api':data.get('api_key'),
                    'user_id':data.get('id'),
                    'username': data.get('username'),
                    'is_login': data.get('islogin'),
                })
            else:
                request.session.clear()
                return JsonResponse({"data": data, 'status':'success', 'message':'you has loggout, please login again'})
            return JsonResponse({"data": data, 'status':'success', 'message':'use this api as new api'})
        else:
            debug(username = username)
            debug(password = password)
            debug("process 3")
            if logout:
                request.session.clear()
                with connection.cursor() as cursor:
                    cursor.execute("update users set logged = '0' where api = '{}'".format(api))
                return JsonResponse({"data": '', 'status':'logout', 'message': 'you has been logout, please login before'})
            request.session.clear()
            return JsonResponse({"data": '', 'status':'error', 'error': 'no username and password'})
    debug("process 4")
    request.session.clear()
    return JsonResponse({"data": data, 'message':'please login before !'})

def logout(request, api = None):
    return login(request, api, logout = True)

def singup(request, api = None, username = None, password = None, email = None):
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    username = username or request.POST.get('username') or request.GET.get('username')
    password = password or request.POST.get('password') or request.GET.get('password')
    email = email or request.POST.get('email') or request.GET.get('email')

    data = check_login(api)
    debug(data = data)
    if not data:
        return JsonResponse({"error": "invalid api key", 'status':'error'})
    user_id = 1
    data1 = {}
    if (username and password and email):
        debug(data = data)
        debug("process singup 1")
        with connection.cursor() as cursor:
            cursor.execute("select * from users where name = '{}'".format(username))
            #data = cursor.fetchall()
            data1 = check_connection(request, cursor)
            debug(data1 = data1, debug = True)
            if data1:
                return JsonResponse({"data": {}, 'status':'error', 'message': 'username is exist !'})
        api = md5.new(username + password).hexdigest()
        request.session.update({'api':api})
        with connection.cursor() as cursor:
            cursor.execute("select * from users order by -id limit 1")
            data1 = check_connection(request, cursor)
            debug(data1 = data1, debug = True)
            if data1:
                user_id = int(data1[0][1])

        with connection.cursor() as cursor:
            cursor.execute("insert into users (user_id, name, password, status, logged, detail_id, api, email) values ('{}','{}','{}','{}','{}','{}','{}','{}')".format(str(user_id + 1), username, password, 'active', '0', str(user_id + 1), api, email))
        with connection.cursor() as cursor:
            cursor.execute("select * from users where api = '{}'".format(api))
            #data = cursor.fetchall()
            data1 = check_connection(request, cursor)
            debug(data1 = data1, debug = True)
    if not data1:
        return JsonResponse({"error": "singup failed", 'status':'error'})

    data = {
        'username': data1[0][2],
        'password': data1[0][3],
        'status': data1[0][4],
        'islogin': data1[0][5],
        'id': data1[0][6],
        'api_key': data1[0][7],
        'email': data1[0][8],
    }
    debug(data1 = data1)
    return JsonResponse({"data": data1, "status":'success', 'message':'please login with username and password'})

def send_email(request, api = None, username = None):
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    username = username or request.session.get('username') or request.GET.get('username') or request.POST.get('username')
    return HttpResponse('send email .....')

def forgot_password(request, api = None, username = None):
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    username = username or request.POST.get('username') or request.GET.get('username')

    data = check_login(api)
    if not data:
        return JsonResponse({"error": "invalid api key", 'status':'error'})

    data = {}
    if (username):
        with connection.cursor() as cursor:
            cursor.execute("select password from users where username = '{}' and api = '{}'".format(username, api))
        data = check_connection(request, cursor)
        debug(data = data, debug = True)
        if data:
            send_email(username)

    return JsonResponse({"data": {}, "status":'success', 'message':'please check youre email'})

def add_product(request, api = None, name = None, category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = category_id or request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    category_id = request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    data1 = check_login2(api)
    data2 = None
    data3 = None
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        #sql = "select * from products where name = '{}' and category_id = '{}' and user_id = '{}'".format(name, category_id, user_id)
        #debug(sql = sql)
        #with connection.cursor() as cursor:
        #    cursor.execute(sql)
        try:
            data2 = products.objects.all().filter(user_id=user_id,name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        debug(user_id = user_id)
        #data = check_connection(request, cursor)
        #debug(data = data)
        debug(data2 = data2)
        if data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'product is exist !'})

        with connection.cursor() as cursor:
            cursor.execute("insert into products (name, category_id, user_id) values ('{}','{}', '{}')".format(name, category_id, user_id))
        #with connection.cursor() as cursor:
        #    cursor.execute("select * from products where name = '{}' and category_id = '{}' and user_id = '{}'".format(name, category_id, user_id))
        try:
            data3 = products.objects.all().filter(user_id=user_id,name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        #data = check_connection(request, cursor)
        #debug(data = data)
        #data = cursor.fetchall()
        debug(data3 = data3)
        if not data3:
            debug(dir_session = request.session.items())
            return JsonResponse({"data": data, 'status':'error', 'error':'failed to add product'})
        data4 = data3.get(name=name)
        data = {
            'name': data4.name,
            'category_id': data4.category_id,
            'user_id': data4.user_id
        }
        return JsonResponse({"data": data, 'status':'success', 'message':'success add product'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to add product'})

def get_product(request, api = None, name = None, category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = category_id or request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    data1 = check_login2(api)
    data2 = None
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        if not name and not category_id:
            with connection.cursor() as cursor:
                cursor.execute("select * from products")
                data2 = check_connection(request, cursor)
                debug(data2 = data2)
            if data2:
                data = []
                for i in data2:
                    data_add = {
                        'name': i[1],
                        'category_id': i[2],
                        'user_id': i[3]
                    }
                    data.append(data_add)
                return JsonResponse({"data": data, 'status':'success'})
            else:
                return JsonResponse({"data": {}, 'status':'success', 'message':'empty product '})

        try:
            if category_id and name:
                data2 = products.objects.all().filter(user_id=user_id,name=name,category_id=category_id)
            elif not category_id and name:
                data2 = products.objects.all().filter(user_id=user_id,name__contains=name)
                if data2 and len(data2) > 1:
                    data = []
                    for i in data2:
                        data_add = {
                            'name': i.name,
                            'category_id': i.category_id,
                            'user_id': i.user_id
                        }
                        data.append(data_add)
                else:
                    data = {
                        'name': data2.get(name = name).name,
                        'category_id': data2.get(name = name).category_id,
                        'user_id': data2.get(name = name).user_id,
                    }
                return JsonResponse({"data": data, 'status':'success'})
            elif category_id and not name:
                data2 = products.objects.all().filter(user_id=user_id,category_id=category_id)

                if data2 and len(data2) > 1:
                    data = []

                    for i in data2:
                        data_add = {
                            'name': i.name,
                            'category_id': i.category_id,
                            'user_id': i.user_id
                        }
                        data.append(data_add)
                else:
                    data = {
                        'name': data2.get(category_id=category_id).name,
                        'category_id': data2.get(category_id=category_id).category_id,
                        'user_id': data2.get(category_id=category_id).user_id,
                    }
                return JsonResponse({"data": data, 'status':'success'})
        except:
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get products !'})
        debug(name = name)
        debug(category_id = category_id)
        debug(user_id = user_id)
        data2 = products.objects.all().filter(user_id=user_id, name = name,category_id=category_id)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'product not exits !'})

        data3 = data2.get(name=name)
        data = {
            'name': data3.name,
            'category_id': data3.category_id,
            'user_id': data3.user_id
        }
        return JsonResponse({"data": data, 'status':'success'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get product'})

def delete_product(request, api = None, name = None, category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = category_id or request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    data1 = check_login2(api)
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        try:
            data2 = products.objects.all().filter(user_id=user_id,name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        debug(user_id = user_id)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'product not exists'})
        data3 = data2.get(name=name)
        data = {
            'name': data3.name,
            'category_id': data3.category_id,
            'user_id': data3.user_id
        }
        data2.delete()
        return JsonResponse({"data": data, 'status':'success', 'message':'successfull delete product'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to delete product'})

def update_product(request, api = None, name = None, category_id = None, new_name = None, new_category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = category_id or request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    new_name = new_name or request.GET.get('newname') or request.GET.get('w') or request.POST.get('newname') or request.POST.get('w')
    new_category_id = new_category_id or request.GET.get('new_categoryid') or request.GET.get('cn') or request.POST.get('new_categoryid') or request.POST.get('cn')
    new_name = new_name or name
    new_category_id = new_category_id or category_id
    data1 = check_login2(api)
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        try:
            data2 = products.objects.all().filter(user_id=user_id,name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        debug(user_id = user_id)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'product not exists'})
        try:
            data2.update(name=new_name, category_id=new_category_id, user_id = user_id)
        except:
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to update products'})
        try:
            data2 = products.objects.all().filter(user_id=user_id,name=new_name,category_id=new_category_id)
            data3 = data2.get(name=new_name)
            data = {
                'name': data3.name,
                'category_id': data3.category_id,
                'user_id': data3.user_id
            }
            return JsonResponse({"data": data, 'status':'success', 'message':'successfull update product'})
        except:
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get product !'})

    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to update product'})


def add_cart(request, api = None, name = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    data1 = check_login2(api)
    debug(data1 = data1)
    data2 = None
    data3 = None
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        try:
            data2 = cart.objects.all().filter(user_id=user_id,name=name)
        except:
            pass
        debug(name = name)
        debug(user_id = user_id)
        debug(data2 = data2)
        if data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'product has been added !'})

        with connection.cursor() as cursor:
            cursor.execute("insert into cart (name, user_id) values ('{}','{}')".format(name, user_id))
        try:
            data3 = cart.objects.all().filter(user_id=user_id,name=name)
        except:
            pass
        debug(name = name)
        debug(data3 = data3)
        if not data3:
            debug(dir_session = request.session.items())
            return JsonResponse({"data": data, 'status':'error', 'error':'failed to add product to cart'})
        data4 = data3.get(name=name)
        data = {
            'name': data4.name,
            'user_id': data4.user_id
        }
        return JsonResponse({"data": data, 'status':'success', 'message':'success add product to cart'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to add product to cart'})

def get_cart(request, api = None, name = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    data1 = check_login2(api)
    data2 = None
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        if not name:
            try:
                data2 = cart.objects.all().filter(user_id=user_id,name=name)
                if not data2:
                    return JsonResponse({"data": {}, 'status':'success', 'message':'empty cart !'})
                if data2 and len(data2) > 1:
                    data = []

                    for i in data2:
                        data_add = {
                            'name': i.name,
                            'user_id': i.user_id
                        }
                        data.append(data_add)
                else:
                    data = {
                        'name': data2.get(user_id=user_id).name,
                        'user_id': data2.get(user_id=user_id).user_id,
                    }
                    return JsonResponse({"data": data, 'status':'success'})
            except:
                print("ERROR:", traceback.format_exc())
                return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get items cart !'})

        debug(name = name)
        debug(user_id = user_id)
        data2 = cart.objects.all().filter(user_id=user_id, name = name)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get cart !'})

        data3 = data2.get(name=name)
        data = {
            'name': data3.name,
            'user_id': data3.user_id
        }
        return JsonResponse({"data": data, 'status':'success'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get card'})

def delete_cart(request, api = None, name = None, category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    data1 = check_login2(api)
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        try:
            data2 = cart.objects.all().filter(user_id=user_id,name=name)
        except:
            pass
        debug(name = name)
        debug(user_id = user_id)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'item card not exists'})
        data3 = data2.get(name=name)
        data = {
            'name': data3.name,
            'user_id': data3.user_id
        }
        data2.delete()
        return JsonResponse({"data": data, 'status':'success', 'message':'successfull delete item product from cart'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to delete product'})

def add_category(request, api = None, name = None, category_id = None):
    api = request.GET.get('api') or request.POST.get('api')
    message = ''
    if not api:
        return JsonResponse({"error": "invalid api key", 'status':'error'})
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = request.GET.get('categoryid') or request.GET.get('category_id') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c') or request.POST.get('category_id')
    if not category_id:
        message += " No category"
    if not name:
        message += " No product name"
    debug(api = api)
    data1 = check_login2(api)
    data2 = None
    data3 = None
    debug(data1 = data1)
    if not data1:
        return JsonResponse({'data':{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api and category_id and name:
        try:
            data2 = category.objects.all().filter(name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        debug(user_id = user_id)
        debug(data2 = data2)
        if data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'category is exist !'})

        with connection.cursor() as cursor:
            cursor.execute("insert into category (name, category_id) values ('{}','{}')".format(name, category_id))
        try:
            data3 = category.objects.all().filter(name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        debug(data3 = data3)
        if not data3:
            debug(dir_session = request.session.items())
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to add category' + ' ' + message.strip()})
        data4 = data3.get(name=name)
        data = {
            'name': data4.name,
            'category_id': data4.category_id,
        }
        return JsonResponse({"data": data, 'status':'success', 'message':'success add category'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to add category'})

def get_category(request, api = None, name = None, category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = category_id or request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    data1 = check_login2(api)
    data2 = None
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        if not name and not category_id:
            with connection.cursor() as cursor:
                cursor.execute("select * from category")
                data2 = check_connection(request, cursor)
                debug(data2 = data2)
            if data2:
                data = []
                for i in data2:
                    data_add = {
                        'name': i[1],
                        'category_id': i[2]
                    }
                    data.append(data_add)
                return JsonResponse({"data": data, 'status':'success'})
            else:
                return JsonResponse({"data": {}, 'status':'success', 'message':'empty category !'})

        try:
            if category_id and name:
                data2 = category.objects.all().filter(name=name,category_id=category_id)
            elif not category_id and name:
                data2 = category.objects.all().filter(name__contains=name)
                if data2 and len(data2) > 1:
                    data = []
                    for i in data2:
                        data_add = {
                            'name': i.name,
                            'category_id': i.category_id,
                        }
                        data.append(data_add)
                else:
                    data = {
                        'name': data2.get(name = name).name,
                        'category_id': data2.get(name = name).category_id,
                    }
                return JsonResponse({"data": data, 'status':'success'})
            elif category_id and not name:
                data2 = category.objects.all().filter(category_id=category_id)

                if data2 and len(data2) > 1:
                    data = []

                    for i in data2:
                        data_add = {
                            'name': i.name,
                            'category_id': i.category_id,
                        }
                        data.append(data_add)
                else:
                    data = {
                        'name': data2.get(category_id=category_id).name,
                        'category_id': data2.get(category_id=category_id).category_id,
                    }
                return JsonResponse({"data": data, 'status':'success'})
        except:
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get category !'})
        debug(name = name)
        debug(category_id = category_id)
        debug(user_id = user_id)
        data2 = category.objects.all().filter(name = name,category_id=category_id)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'category not exits !'})

        data3 = data2.get(name=name)
        data = {
            'name': data3.name,
            'category_id': data3.category_id,
        }
        return JsonResponse({"data": data, 'status':'success'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get category'})

def delete_category(request, api = None, name = None, category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = category_id or request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    data1 = check_login2(api)
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        try:
            data2 = category.objects.all().filter(name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'category not exists'})
        data3 = data2.get(name=name)
        data = {
            'name': data3.name,
            'category_id': data3.category_id,
        }
        data2.delete()
        return JsonResponse({"data": data, 'status':'success', 'message':'successfull delete category'})
    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to delete category'})

def update_category(request, api = None, name = None, category_id = None, new_name = None, new_category_id = None):
    if not request.session.get('is_login'):
        if not request.GET.get('api') or request.POST.get('api'):
            return JsonResponse({"error": "invalid api key", 'status':'error'})
    api = api or request.session.get('api') or request.GET.get('api') or request.POST.get('api')
    name = name or request.GET.get('name') or request.GET.get('n') or request.POST.get('name') or request.POST.get('n')
    category_id = category_id or request.GET.get('categoryid') or request.GET.get('c') or request.POST.get('categoryid') or request.POST.get('c')
    new_name = new_name or request.GET.get('newname') or request.GET.get('w') or request.POST.get('newname') or request.POST.get('w')
    new_category_id = new_category_id or request.GET.get('new_categoryid') or request.GET.get('cn') or request.POST.get('new_categoryid') or request.POST.get('cn')
    new_name = new_name or name
    new_category_id = new_category_id or category_id
    data1 = check_login2(api)
    debug(data1 = data1)
    if not data1:
        return JsonResponse({data:{}, "error": "please login before", 'status':'error'})
    user_id = request.session.get('user_id')
    if data1 and not isinstance(data1[-1], datetime.datetime):
        user_id = data1[0][1]
    else:
        return JsonResponse({"data": data, 'status':'error', 'error':'please login before !'})
    debug(user_id = user_id)
    if data1 and api:
        try:
            data2 = category.objects.all().filter(name=name,category_id=category_id)
        except:
            pass
        debug(name = name)
        debug(category_id = category_id)
        if not data2:
            return JsonResponse({"data": {}, 'status':'error', 'error':'category not exists'})
        try:
            data2.update(name=new_name, category_id=new_category_id)
        except:
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to update category'})
        try:
            data2 = category.objects.all().filter(name=new_name,category_id=new_category_id)
            data3 = data2.get(name=new_name)
            data = {
                'name': data3.name,
                'category_id': data3.category_id,
            }
            return JsonResponse({"data": data, 'status':'success', 'message':'successfull update category'})
        except:
            return JsonResponse({"data": {}, 'status':'error', 'error':'failed to get category !'})

    else:
        if not user_id:
            return JsonResponse({"data": {}, 'status':'error', 'error':'please login again'})
        return JsonResponse({"data": {}, 'status':'error', 'error':'failed to update category'})























def test(request):
    return render(request, 'test.html', {})


def check_pass(request, password, **kwargs):
    print("Inside decorator")

    def inner(func):

        # code functionality here
        print("Inside inner function")
        # print("password", kwargs['password'])
        print("password", [password])

        data = func(password)

    # returning inner function
    return inner

@check_pass("requests", "test")
def my_func(password):
    if password == 'test':
        print("access granted !")
    else:
        print("access faile{%endblock%}d  !")
    # print("Inside actual function")

def check(request, func = None, **kwargs):
    def process(func):
        func(request, **kwargs)

    if not request and func:
        return login(request, "Anda harus login terlebih dahulu [0000]")
    username = request.session.get('vendor_code') or request.session.get('username')
    password = request.session.get('password') or request.COOKIES.get('password')
    if not username and not password:
        with connection.cursor() as cursor:
            cursor.execute("SELECT TOP 1 * FROM [DB_EMAIL].[dbo].[VIS_UserLogin2] WHERE [DB_EMAIL].[dbo].[VIS_UserLogin2].[UserNameLogin] = '{}' OR [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '{}' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[Status] = 'Active'".format(username, username))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            debug(data = data, debug = True)
        if data:
            username = data[0][-3] or ''
            password = data[0][-5] or ''
            is_changed = data[0][-2] or ''
            if func:
                return username, password, is_changed
    if not username or not password:
        return login("Anda harus login terlebih [0001]")
    elif username and crypt.encrypt(password, settings.ENCRYPT_KEY) == '12345678':
        return change_pass(request, "Anda menggunakan Password default, silahkan ganti password terlebih dahulu [0001]")
    elif username and (is_changed == '1' or is_changed == 1 or not is_changed):
        return change_pass(request, "Demi keamanan, update kembali password anda [0001]")
    else:
        if func:
            return process
        else:
            return True

def time_calc(actime):
    '''
    	@actime: datetime.object
    '''
    #total_seconds = (datetime.datetime.now() - actime.replace(tzinfo = None)).total_seconds()
    #total_seconds = (datetime.datetime.now().timestamp() - actime.replace(tzinfo = None).timestamp())
    #debug(total_seconds = total_seconds, debug = True)
    a = pytz.timezone(settings.TIME_ZONE or "Asia/Jakarta")
    c = actime.astimezone(a)
    total_seconds = (datetime.datetime.now() - datetime.datetime.strptime(datetime.datetime.strftime(c, '%Y-%m-%d %H:%M:%S.%f'), '%Y-%m-%d %H:%M:%S.%f')).total_seconds()
    return total_seconds

def check_session(request):
    ip = get_client_ip(request)
    debug(ip = ip, debug = True)
    username = request.session.get('vendor_code') or request.session.get('username')
    debug(username = username, debug = True)
    if not username:
        message = "Silahkan login kembali !"
        debug(message = message, debug = True)
        add_log(request, "check_session", message)
        #sys.exit()
        request.session.clear()
        request.COOKIES.clear()
        return "login", message
        #return login(request, message)
    if not ip:
        message = "Anda tidak dapat login, silahkan hub administrator !"
        debug(message = message, debug = True)
        add_log(request, "check_session", message)
        #sys.exit()
        request.session.clear()
        request.COOKIES.clear()
        return "login", message
        #return login(request, message)
    debug(ip = ip, debug = True)
    debug(SESSION = request.session.items(), debug = True)
    debug(COOKIES = request.COOKIES, debug = True)
    data = {}
    message = ''
    actime = ''
    if request.COOKIES.get('sessionid'):
        debug("Check Type 1", debug = True)
        debug(sessionid = request.COOKIES.get('sessionid'), debug = True)
        user_agent = request.META['HTTP_USER_AGENT']
        debug(user_agent = user_agent, debug = True)
        data = vlogs.objects.filter(ip_address=ip, session_id=request.COOKIES.get('sessionid'), user_agent = request.META['HTTP_USER_AGENT']).order_by('-time')
        debug(data = data, debug = True)
        if data:
            data = data[0]
        debug(data = data, debug = True)
        #data = vlogs.objects.filter(ip_address=ip, username = username, session_id=request.COOKIES.get('sessionid'), user_agent = user_agent, module = 'login', message = 'granted').order_by('-time')
        #with connection.cursor() as cursor:
            #user_agent = request.META['HTTP_USER_AGENT']
            #cursor.execute(f"SELECT * FROM VIS_logs WHERE username = '{username}', session_id = '{request.COOKIES.get('sessionid')}', user_agent = '{user_agent}', module = 'login', message = 'granted'")
            #data = check_connection(request, cursor)
            #debug(data = data, debug = True)
        print("DATA 1:", data)
        debug(data = data, debug = True)
    else:
        debug("Check Type 2", debug = True)
        user_agent = request.META['HTTP_USER_AGENT']
        debug(user_agent = user_agent, debug = True)
        data = vlogs.objects.filter(ip_address=ip, username = username, user_agent = user_agent, module = 'login', message = 'granted').order_by('-time')
        debug(data = data, debug = True)

    print("DATA:", data)
    debug(data = data, debug = True)

    if not data:
        message = 'Silahkan login terlebih dahulu !'
        #return login(request, message)
        request.session.clear()
        request.COOKIES.clear()
        return "login", message
    #if data:
        #debug(data = data, debug = True)
        #data = data[0]
    debug(data = data, debug = True)
    debug(message = message, debug = True)

    try:
        try:
            actime = time_calc(data[0].time)
        except:
            actime = time_calc(data.time)
        debug(actime = actime, debug = True)
    except:
        debug(ERROR = traceback.format_exc(), debug = True)
        access_time = request.COOKIES.get('access') or request.session.get('access')
        debug(access_time = access_time, debug = True)
        if isinstance(access_time, bytes):
            access_time = access_time.decode('utf-8')
        debug(access_time = access_time, debug = True)
        if access_time:
            access = crypt.decrypt(access_time, settings.ENCRYPT_KEY)
            debug(access = access, debug = True)
            if isinstance(access, bytes):
                access = access.decode('utf-8')
            debug(access = access, debug = True)
            debug(check_access_x = check_access(access), debug = True)
            if check_access(access) > settings.MAX_TIME:
                message = "Session anda telah berakhir ! [1]"
                debug(message = message, debug = True)
                add_log(request, "check_session", message)
                request.session.clear()
                request.COOKIES.clear()
                return "login", message
                #return login(request, message)
    debug(actime = actime, debug = True)
    #actime = None
    if not actime:
        message = 'Session anda telah berakhir silahkan login terlebih dahulu !'
        request.session.clear()
        request.COOKIES.clear()
        return "login", message
        #return logout(request, message)
    if int(settings.MAX_TIME) < actime:
        message = "Session anda telah berakhir ! [1]"
        debug(message = message, debug = True)
        add_log(request, "check_session", message)
        request.session.clear()
        request.COOKIES.clear()
        return "login", message
        #return login(request, message)
    return "", ""

def check_access(access):
    term = settings.MAX_TIME or 0
    debug(access = access, debug = True)
    access = datetime.datetime.strptime(access, '%Y-%m-%d %H:%M:%S.%f')
    debug(access = access, debug = True)
    #total_seconds = (datetime.datetime.now() - access).total_seconds()
    total_seconds = time_calc(access)
    debug(total_seconds = total_seconds, debug = True)
    if total_seconds:
        if term == 0:
            return True
        elif str(total_seconds)[0] == '-':
            return False
        elif int(total_seconds) > term:
            return False
        else:
            return True
    return False

def check_access_enc(access):
    access = crypt.decrypt(access, settings.ENCRYPT_KEY)
    debug(access = access, debug = True)
    access = datetime.datetime.strptime(access, '%Y-%m-%d %H:%M:%S.%f')
    debug(access = access, debug = True)
    #total_seconds = (datetime.datetime.now() - access).total_seconds()
    total_seconds = time_calc(access)
    debug(total_seconds = total_seconds, debug = True)
    return total_seconds
    # if total_seconds:
    # 	if str(total_seconds)[0] == '-':
    # 		return False
    # 	else:
    # 		return True
    # return False

def check_login1(request):
    access_time = request.COOKIES.get('access') or request.session.get('access')
    debug(access_time = access_time, debug = True)
    if isinstance(access_time, bytes):
        access_time = access_time.decode('utf-8')
    debug(access_time = access_time, debug = True)
    cs = check_session(request)
    debug(cs = cs, debug = True)
    debug(Session = request.session.items(), debug = True)
    if len(cs[0]) > 0:
        #return getattr(views, cs[0])(request, cs[1])
        return cs
    if not request.session:
        return login(request,  "Silahkan login kembali, session anda telah berakhir !")
    if access_time and len(cs[0]) == 0:
        # access = request.COOKIES.update({'access': crypt.decrypt(access_time, settings.ENCRYPT_KEY)})
        access = crypt.decrypt(access_time, settings.ENCRYPT_KEY)
        debug(access = access, debug = True)
        if isinstance(access, bytes):
            access = access.decode('utf-8')
        debug(access = access, debug = True)
        debug(check_access_x = check_access(access), debug = True)
        try:
            MAX_TIMEOUT = int(settings.MAX_TIMEOUT) or 600
        except:
            MAX_TIMEOUT = 600
        if check_access(access) > MAX_TIMEOUT:
            # return login(request, "Session anda telah berakhir silahkan login kembali !")
            add_log(request, "check_login", "Session anda telah berakhir silahkan login kembali !")
            return "login", "Session anda telah berakhir silahkan login kembali !"
        else:
            add_log(request, "check_login", "true")
            return True, ""
    else:
        # return login(request, "silahkan login kembali terlebih dahulu !")

        username = request.session.get('vendor_code') or request.session.get('username')
        password = request.session.get('password') or request.COOKIES.get('password')
        status = request.session.get('status') or request.COOKIES.get('status')
        access = request.session.get('access') or request.COOKIES.get('access')
        # is_changed = request.session.get('is_changed') or request.COOKIES.get('is_changed')
        # if is_changed:
        # 	is_changed = str(is_changed)
        vendor_name = request.session.get('vendor_name') or request.COOKIES.get('vendor_name')
        is_login = request.session.get('is_login') or request.COOKIES.get('is_login')
        if is_login:
            is_login = str(is_login)
        debug(username = username, debug = True)
        debug(password = password, debug = True)
        debug(status = status, debug = True)
        # debug(is_changed = is_changed, debug = True)
        debug(vendor_name = vendor_name, debug = True)
        debug(is_login = is_login, debug = True)
        data = ''
        with connection.cursor() as cursor:
            cursor.execute("SELECT TOP 1 * FROM [DB_EMAIL].[dbo].[VIS_UserLogin2] WHERE NamaVendor  like '%Super User%' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[UserNameLogin] = '{}' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '000000000' OR [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[Status] = 'Active'".format(username))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            debug(data = data, debug = True)
            if data:
                is_changed = data[0][-2]
            else:
                is_changed = ''

        if len(data) > 0:
            if username and password and status == 'Active' and is_changed == "1" and is_login == "1":
                debug("data pass", debug = True)
                debug('username and password and status == Active and is_changed == "1" and is_login == "1"', debug = True)
                data_password = data[0][2].encode('utf-8')
                debug(data_password = data_password, debug = True)
                debug(password = password, debug = True)
                debug(password_bytes = bytes(password, encoding='utf-8'), debug = True)
                # debug(password_decrypt = password_decrypt, debug = True)
                # if bytes(password, encoding='utf-8') == data_password:
                if not bytes(password, encoding='utf-8') == data_password or not password == data_password:
                    debug("Password is Not Same !")
                    # return login(request, "Session anda telah berakhir !")
                    message = "Session anda telah berakhir !"
                    add_log(request, "check_login", message)
                    return "login", message

            elif is_changed == '0' or not is_changed or is_changed == 0:
                # return change_pass(request, "Anda harus mengganti password anda terlebih dahulu, password anda masih menggunakan password default")
                message = "Anda harus mengganti password anda terlebih dahulu, password anda masih menggunakan password default"
                add_log(request, "check_login", message)
                return "change_pass", message
            elif (is_changed == '1' or not is_changed or is_changed == 1) and password == '12345678':
                debug("change is 1", debug = True)
                message = "Anda masih menggunakan password default silahkan ganti password anda terlebih dahulu"
                add_log(request, "check_login", message)
                # return change_pass(request, "Anda masih menggunakan password default silahkan ganti password anda terlebih dahulu")
                return "change_pass", message
            elif not status == 'Active':
                debug("account tidak activ !", debug = True)
                # return login(request, "Anda telah di non aktivkan dari system ini silahkan hub administrator")
                message = "Anda telah di non aktivkan dari system ini silahkan hub administrator"
                add_log(request, "check_login", message)
                return "login", message
            # else:
                # debug("harus login dulu", debug = True)
                # return login(request)
                # return "login", ""
            #return False, ""
        else:
            if not username and not password and not status == 'Active' and not is_changed == "1" and not is_login == "1":
                debug("No Data", debug = True)
                message = "Session anda telah berakhir, silahkan login kembali"
            else:
                message = "Anda tidak terdaftar dalam system ini, silahkan hub administrator !"
            debug(message = message, debug = True)
            # return login(request, message)
            add_log(request, "check_login", message)
            return "login", message
            # return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})
            # return redirect('/')

def check_change(request, func):
    username = request.session.get('vendor_code') or request.session.get('username')
    password = request.session.get('password') or request.COOKIES.get('password')
    if not username or not password:
        with connection.cursor() as cursor:
            cursor.execute("SELECT TOP 1 * FROM [DB_EMAIL].[dbo].[VIS_UserLogin2] WHERE [DB_EMAIL].[dbo].[VIS_UserLogin2].[UserNameLogin] = '{}' OR [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '{}' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[Status] = 'Active'".format(username, username))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            debug(data = data, debug = True)
        if data:
            username = data[0][-3]
            password = data[0][-5]
    if not username or not password:
        message = "Anda harus login terlebih [0002]"
        add_log(request, "check_change", message)
        return login(request, message)

def profile(request, message = ''):
    request.session.update({'prev': request.get_full_path()})
    cc = check_login(request)
    debug(cc = cc, debug = True)
    if cc[0] and not isinstance(cc[0], bool):
        add_log(request, "profile", "Session telah berakhir")
        return getattr(views, cc[0])(request, cc[1])
    username = request.session.get('vendor_code') or request.session.get('username')
    debug(username = username, debug = True)

    with connection.cursor() as cursor:
        cursor.execute(f"EXEC TMSP_VIS_Business_Partner_Profile @KodeVendor = '{username}'")
        #data = cursor.fetchall()
        data = check_connection(request, cursor)
        #debug(data = data, debug = True)

        #debug(data = str(data), debug = True)
        data = ['' if v is None else v for v in data]
        debug(data = data, debug = True)
        data = (data)

        #try:
            #data = str(data).replace('None', '')
            #data = list(eval(data))
        #except:
            #try:
                #data = str(data).replace('None', "")
                #data = list(eval(data))
            #except:
                #data = str(data).replace('None', '""')
                #data = list(eval(data))

        #debug(data = data, debug = True)

    return render(request, 'profile.html', {'data': data, 'message': message,})

def profile_edit(request, message = ''):
    cc = check_login(request)
    debug(cc = cc, debug = True)
    if cc[0] and not isinstance(cc[0], bool):
        add_log(request, "profile_edit", "Session telah berakhir")
        return getattr(views, cc[0])(request, cc[1])

    data = ''
    username = request.session.get('vendor_code') or request.session.get('username') or request.POST.get('u') or request.POST.get('username') or request.GET.get('u') or request.GET.get('username')
    debug(username = username, debug = True)
    if username:
        with connection.cursor() as cursor:
            cursor.execute(f"EXEC TMSP_VIS_Business_Partner_Profile @KodeVendor = '{username}'")
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            debug(data = data, debug = True)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)

    tax_1 = data[0][2]
    addr_1 = data[0][3]
    tlp1_1 = data[0][4]
    tlp2_1 = data[0][5]
    mph_1 = data[0][6]
    email_1 = data[0][7]
    pterm_1 = data[0][8]
    bank_1 = data[0][9]
    att_1 = data[0][10]
    userImage_1 = data[0][11]

    uploaded_file_url = ''

    if data:
        notify.send("VIS", f"Data is Exits", "profile_edit", "error")

        tax = request.POST.get('tax') or request.GET.get('tax')
        debug(tax = tax, debug = True)
        addr = request.POST.get('addr') or request.GET.get('addr')
        debug(addr = addr, debug = True)
        tlp1 = request.POST.get('tlp1') or request.GET.get('tlp1')
        debug(tlp1 = tlp1, debug = True)
        tlp2 = request.POST.get('tlp2') or request.GET.get('tlp2')
        debug(tlp2 = tlp2, debug = True)
        mph = request.POST.get('mph') or request.GET.get('mph')
        debug(mph = mph, debug = True)
        email = request.POST.get('email') or request.GET.get('email')
        debug(email = email, debug = True)
        pterm = request.POST.get('pterm') or request.GET.get('pterm')
        debug(pterm = pterm, debug = True)
        bank = request.POST.get('bank') or request.GET.get('bank')
        debug(bank = bank, debug = True)
        att = request.POST.get('att') or request.GET.get('att')
        debug(attr = att, debug = True)
        userImage = request.POST.get('userImage') or request.GET.get('userImage')
        if userImage:
            debug(userImage = len(userImage), debug = True)
        else:
            debug(userImage = userImage, debug = True)
        photo = request.POST.get('data-img')
        if photo:
            debug(photo = len(photo), debug = True)
        else:
            debug(photo = photo, debug = True)
        debug(POST_Keys = request.POST.keys(), debug = True)
    else:
        notify.send("VIS", f"No Data", "profile_edit", "error")
    if tax or addr or tlp1 or tlp2 or mph or email or pterm or bank:
        if (not tax == tax_1 or\
                    not addr == addr_1 or\
                   not tlp1 == tlp1_1 or\
                   not tlp2 == tlp2_1 or\
                   not mph == mph_1 or\
                   not email == email_1 or\
                   not pterm == pterm_1 or\
                   not bank == bank_1) or\
                   request.FILES.get('att') or request.FILES.get('userImage'): # or\
            #not att or userImage:

            #with open('/tmp/request.txt', 'w') as f:
                #f.write(str(request.FILES))
            #with open('/tmp/request_dir.txt', 'w') as f:
                #f.write(str(dir(request.FILES)))
            #with open('/tmp/request_items.txt', 'w') as f:
                #f.write(str(request.FILES.items()))
            #with open('/tmp/request_keys.txt', 'w') as f:
                #f.write(str(request.FILES.keys()))
            #with open('/tmp/request_userimage.txt', 'w') as f:
                #f.write(str(request.FILES.get('userImage')))
            try:
                if request.FILES.get('att'):
                    myfile = request.FILES['att']
                    if myfile._size > settings.MAX_UPLOAD_SIZE:
                        raise forms.ValidationError(_('Please keep filesize under %s. Current filesize %s') % (filesizeformat(settings.MAX_UPLOAD_SIZE), filesizeformat(myfile._size)))
                    fs = FileSystemStorage()
                    filename = fs.save(myfile.name, myfile)
                    notify.send("VIS", f"myfile1.name = {myfile.name}", "profile_edit", "Upload attachment")
                    debug(filename = filename, debug = True)
                    notify.send("VIS", f"filename = {filename}", "profile_edit", "Upload attachment")
                    uploaded_file_url = fs.url(filename)
                    debug(uploaded_file_url = uploaded_file_url, debug = True)
                    notify.send("VIS", f"uploaded_file_url = {uploaded_file_url}", "profile_edit", "Upload attachment")
                    if message:
                        message += " | Upload file attachment success"
                    else:
                        message = "Upload file attachment success"
            except:
                notify.send("VIS", f"ERROR = {traceback.format_exc()}", "profile_edit", "Upload file attachment gagal")
                if message:
                    message += " | Upload file attachment gagal"
                else:
                    message = "Upload file attachment gagal"

            try:
                if request.FILES.get('userImage'):
                    myfile1 = request.FILES['userImage']
                    if myfile1._size > settings.MAX_UPLOAD_SIZE:
                        raise forms.ValidationError(_('Please keep filesize under %s. Current filesize %s') % (filesizeformat(settings.MAX_UPLOAD_SIZE), filesizeformat(myfile1._size)))
                    fs1 = FileSystemStorage()
                    #filename1 = fs1.save(myfile1.name, myfile1)
                    notify.send("VIS", f"myfile1.name = {myfile1.name}", "profile_edit", "Upload attachment")
                    #if os.path.isfile(settings.MEDIA_ROOT, os.path.join(username, "person" + os.path.splitext(myfile1.name)[-1])):
                        #try:
                            #os.remove(settings.MEDIA_ROOT, os.path.join(username, "person" + os.path.splitext(myfile1.name)[-1]))
                        #except:
                            #pass
                    filename1 = fs1.save(os.path.join(username, "person" + os.path.splitext(myfile1.name)[-1]), myfile1)
                    notify.send("VIS", f"filename1 = {filename1}", "profile_edit", "Upload attachment")
                    debug(filename1 = filename1, debug = True)
                    uploaded_file_url1 = fs1.url(filename1)
                    debug(uploaded_file_url1 = uploaded_file_url1, debug = True)
                    notify.send("VIS", f"uploaded_file_url1 = {uploaded_file_url1}", "profile_edit", "Upload userImage")
                    if message:
                        message += " | Upload gambar profile success"
                    else:
                        message = "Upload gambar profile success"
            except:
                notify.send("VIS", f"ERROR = {traceback.format_exc()}", "profile_edit", "Upload userImage")
                if message:
                    message += " | Upload gambar profile gagal"
                else:
                    message = "Upload gambar profile gagal"

            with connection.cursor() as cursor:
                #cursor.execute(f"TMSP_VIS_Business_Partner_Profile @KodeVendor = '{username}_1'")
                cursor.execute(f"EXEC Update_VIS_Profile @vendorcode = '{username}' , @federaltaxid = '{tax or ''}', @address = '{addr or ''}', @tlp1 = '{tlp1 or ''}' , @tlp2 = '{tlp2 or ''}', @mobilephone = '{mph or ''}', @email = '{email or ''}', @paymentterm = '{pterm or ''}', @bankaccount = '{bank or ''}', @att = '{uploaded_file_url or att_1}', @fotoprofile = '{photo or ''}'")
                #data = cursor.fetchall()
                data = check_connection(request, cursor)
                debug(data = data, debug = True)
                debug(mph = mph, debug = True)
                if data:
                    if message:
                        message += " | SUCCESS"
                    else:
                        message = "SUCCESS"
                else:
                    if message:
                        message += " | GAGAL"
                    else:
                        message = "GAGAL"

            debug(message = message, debug = True)
            debug(uploaded_file_url = uploaded_file_url, debug = True)
            return profile(request, message)
    else:
        with connection.cursor() as cursor:
            cursor.execute(f"EXEC TMSP_VIS_Business_Partner_Profile @KodeVendor = '{username}'")
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            debug(data = data, debug = True)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)
            data = (data)
            #try:
                #data = str(data).replace('None', '')
                #debug(data = str(data), debug = True)
                #data = list(eval(data))
                #debug(data = data, debug = True)
            #except:
                #data = str(data).replace('None', "")
                #debug(data = str(data), debug = True)
                #data = list(eval(data))
                #debug(data = data, debug = True)

        return render(request, 'edit_profile.html', {'data': data,})

def logout1(request, message = ''):
    debug(session_items = request.session.items(), debug = True)
    debug(COOKIES = request.COOKIES, debug = True)

    access_time = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S.%f') #YYYY-MM-DD HH:MM[:ss
    debug(access_time=access_time, debug=True)
    ses_ck = request.COOKIES.get('sessionid')
    ses_u = request.session.get('vendor_code') or request.session.get('username')
    ses_ip = get_client_ip(request)
    ses_ug = request.META['HTTP_USER_AGENT']
    ses_act = access_time
    debug(ses_ck=ses_ck)
    debug(ses_u=ses_u)
    debug(ses_ip=ses_ip)
    debug(ses_ug=ses_ug)
    debug(ses_act=ses_act)
    se = VisSessions(session_id = ses_ck, username = ses_u, ip_address = ses_ip, user_agent = ses_ug, last_activity = ses_act, is_login = 0)

    debug("save data to session logout", debug = True)
    se.save()

    request.session.clear()
    request.COOKIES.clear()
    debug(session_items = request.session.items(), debug = True)
    debug(COOKIES = request.COOKIES, debug = True)
    debug(session = request.session, debug = True)
    debug(session_items = request.session.items(), debug = True)
    debug(dir_session = dir(request.session), debug = True)
    debug(COOKIES = request.COOKIES, debug = True)

    if not message:
        message = "Anda telah logout !"

    return login(request, message)

    # return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})

def version01(request):
    response = redirect('http://10.1.0.56:8080/VIS')
    return response

def test_pass(request):
    return render(request, 'test_pass.html', {})

def test_error(request):
    return render(request, 'database_error.html', {})

def login1(request, message = '', username = ''):
    # check_login(request)
    #request.session.clear()
    #request.COOKIES.clear()
    # debug(dir_request = dir(request), debug = True)
    # debug(dir_request = dir(request.session), debug = True)
    # debug(dir_request = dir(request.COOKIES), debug = True)
    # debug(dir_request = dir(request.GET))



    debug(post = request.POST, debug = True)
    debug(post = request.POST.get('username'), debug = True)
    #return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})
    debug(session = request.session.items(), debug = True)
    debug(cookies = request.COOKIES, debug = True)
    debug("login lagi", debug = True)
    is_operator = False
    vc_number = ''
    password = ''
    if request.POST:
        is_root = check_is_root(request)
        debug(is_root = is_root, debug = True)
        if request.POST.get('vc_number'):
            request.session['is_operator'] = "1"
            is_operator = True
            vc_number = request.POST.get('vc_number')
        if is_root:
            request.session['username'] = request.POST.get('username')
            request.session['vendor_code'] = request.POST.get('username')
            request.session['password'] = crypt.encrypt(request.POST.get('password'), settings.ENCRYPT_KEY)
            request.session['status'] = "Active"
            request.session['is_changed'] = '1'
            request.session['vendor_name'] = "Super User"
            request.session['is_login'] = "1"
            request.session['priv'] = '0'

            request.COOKIES.update({'username':request.POST.get('username')})
            request.COOKIES.update({'vendor_code':request.POST.get('username')})
            request.COOKIES.update({'password':crypt.encrypt(request.POST.get('password'), settings.ENCRYPT_KEY)})
            request.COOKIES.update({'status':"Active"})
            request.COOKIES.update({'is_changed':'1'})
            request.COOKIES.update({'vendor_name':"Super User"})
            request.COOKIES.update({'is_login':"1"})
            request.COOKIES.update({'priv':'0'})
            return show_all_pass(request)

        username = username or request.POST.get('username')
        #is_login = request.session.get("is_login") or request.COOKIES.get("is_login")
        debug(username = username, debug = True)
        password = request.POST.get('password')
        debug(password = password, debug = True)
    username = username or request.session.get('vendor_code') or request.session.get('username')
    if not password:
        debug(session_items = request.session.items(), debug = True)
        debug(COOKIES = request.COOKIES, debug = True)
        password = password or request.session.get('password') or request.COOKIES.get('password')
        if password:
            password = crypt.decrypt(password, settings.ENCRYPT_KEY)

    debug(username = username, debug = True)
    debug(session_items = request.session.items(), debug = True)
    debug(COOKIES = request.COOKIES, debug = True)
    if not request.session:
        message = message or 'Session anda telah berakhir, silahkan login kembali'
        debug(message = message, debug = True)
        add_log(request, "login",  message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})

    debug(message = message, debug = True)
    data = []

    with connection.cursor() as cursor:
        if is_operator and vc_number:
            cursor.execute("SELECT TOP 1 * FROM [DB_EMAIL].[dbo].[VIS_UserLogin2] WHERE [DB_EMAIL].[dbo].[VIS_UserLogin2].[UserNameLogin] = '{}' OR [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '{}' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[Status] = 'Active'".format(vc_number, vc_number))
        else:
            cursor.execute("SELECT TOP 1 * FROM [DB_EMAIL].[dbo].[VIS_UserLogin2] WHERE [DB_EMAIL].[dbo].[VIS_UserLogin2].[UserNameLogin] = '{}' OR [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '{}' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[Status] = 'Active'".format(username, username))

        #data = cursor.fetchall()
        data = check_connection(request, cursor)
        debug(data = data, debug = True)
    debug(data = data, debug = True)
    debug(username = username, debug = True)
    if not data and request.POST.get('username'):
        message = "Anda tidak terdaftar dalam system ini !"
        debug(message = message, debug = True)
        add_log(request, "login",  message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})
    elif not data and username:
        #message = "Anda tidak terdaftar dalam system ini !"
        if not request.POST.get('username'):# == crypt.decrypt(data[0][2].encode('utf-8'), settings.ENCRYPT_KEY):
            message = "Password anda salah !"
        #elif not request.session.items():# or not request.COOKIES:
            #message = "Session anda telah berakhir silahkan login kembali !"
            #message = "Anda tidak terdaftar dalam system ini !"
        else:
            message = "Session anda telah berakhir silahkan login kembali !"
            #message = "Anda tidak terdaftar dalam system ini !"
        debug(message = message, debug = True)
        add_log(request, "login",  message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})
    elif not data and not username:
        if not message:
            message = "Silahkan login terlebih dahulu ! (password default: 12345678)"
        #message = "Session anda telah berakhir silahkan login kembali !"
        debug(message = message, debug = True)
        add_log(request, "login", message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})
    elif not data:
        message = "no data !, Anda tidak terdaftar dalam system ini ! [1]"
        debug(message = message, debug = True)
        add_log(request, "login", message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})

    is_changed = data[0][-3] or ''
    if is_changed:
        is_changed = str(is_changed)
    debug(is_changed = is_changed, debug = True)
    data_password = data[0][2].encode('utf-8')
    debug(data_password = data_password, debug = True)
    # if sys.version_info.major == 3:
    # 	data_password = data_password.encode()
    password_decrypt = crypt.decrypt(data_password, settings.ENCRYPT_KEY)
    debug(password_decrypt = password_decrypt, debug = True)
    debug(password = password, debug = True)
    username_from_db = data[0][1]
    debug(username_from_db = username_from_db, debug = True)
    data_status = data[0][-2]
    debug(data_status = data_status, debug = True)

    debug(password = password, debug = True)
    debug(password_decrypt = password_decrypt, debug = True)

    if username_from_db == username and password_decrypt == password and data[0][-2] == 'Active':
        request.session['username'] = username
        request.session['vendor_code'] = username
        request.session['password'] = data[0][-6]
        request.session['status'] = data[0][-2]
        request.session['is_changed'] = is_changed
        request.session['vendor_name'] = data[0][3]
        request.session['is_login'] = "1"
        request.session['priv'] = data[0][-1]

        request.COOKIES.update({'username':username})
        request.COOKIES.update({'vendor_code':username})
        request.COOKIES.update({'password':data[0][-6]})
        request.COOKIES.update({'status':data[0][-2]})
        request.COOKIES.update({'is_changed':is_changed})
        request.COOKIES.update({'vendor_name':data[0][3]})
        request.COOKIES.update({'is_login':"1"})
        request.COOKIES.update({'priv':data[0][-1]})

        if is_changed == '0' or not is_changed or is_changed == 0:
            message = "Anda harus mengganti password anda terlebih dahulu, pastikan password anda terdiri dari angka, huruf besar dan simbol minimal 1, silahkan logout terlebih dahulu jika ingin menggunakan atau mengganti dengan username yang lain"
            add_log(request, "login", message)
            return change_pass(request, message)
        elif (is_changed == '1' or not is_changed or is_changed == 1) and password_decrypt == '12345678':
            message = "Anda masih menggunakan password default silahkan ganti password anda terlebih dahulu, Anda harus mengganti password anda terlebih dahulu, pastikan password anda terdiri dari angka, huruf besar dan simbol minimal 1"
            add_log(request, "login", message)
            return change_pass(request, message)

        debug(COOKIES = request.COOKIES, debug = True)
        access_time = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S.%f') #YYYY-MM-DD HH:MM[:ss
        request.COOKIES.update({'access': crypt.encrypt(access_time, settings.ENCRYPT_KEY)})
        request.session.update({'access': crypt.encrypt(access_time, settings.ENCRYPT_KEY)})
        debug(session_id = request.session.items(),  debug = True)
        debug(COOKIES = request.COOKIES,  debug = True)
        debug(SESSION = request.session.items(),  debug = True)
        #if not request.COOKIES.get('sessionid'):
            #debug("not request.COOKIES.get('sessionid')", debug =  True)
            #message = "Login anda salah"
            #debug(message = message,  debug =  True)
            #add_log(request, "login", message)
            #request.session.clear()
            #request.COOKIES.clear()
            #return render(request, 'login1.html', {'title':'Vendor Information System', 'message': message})
        se = VisSessions(session_id = request.COOKIES.get('sessionid'), username = username, ip_address = get_client_ip(request), user_agent = request.META['HTTP_USER_AGENT'], last_activity = access_time, is_login = 1)
        debug("save data to session", debug = True)
        se.save()

        request.session.update({'current': 'index'})
        request.COOKIES.update({'current': 'index'})
        add_log(request, "login", "granted")
        debug("to Index", debug = True)
        #if request.session.get('prev'):
            #return redirect(f"/{request.session.get('prev')}")
        #else:
        #is_root =  check_is_root(request)
        #debug(is_root = is_root, debug = True)
        #notify.send("VIS1", is_root, "vis", "check")
        #if isinstance(is_root, bool):
            #return show_all_pass(request)

        return index(request, username)
    elif not username_from_db == username:
        message = "Username anda salah !"
        add_log(request, "login", message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message': message})
    elif not password_decrypt == password and (request.session.get('vendor_code') or request.session.get('username')):
        message = "Password anda salah !"
        add_log(request, "login", message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message': message})
    elif not password_decrypt == password and (request.session.get('vendor_code') or request.session.get('username')):
        message = "Session and telah berakhir, silahkan login kembali !"
        add_log(request, "login", message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message': message})
    elif not data_status == 'Active':
        message = "Account anda telah dinon-aktivkan, silahkan hub administrator !"
        add_log(request, "login", message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message': message})
    elif not password_decrypt == password:
        message = "Password anda salah !"
        add_log(request, "login", message)
        return render(request, 'login1.html', {'title':'Vendor Information System', 'message': message})
    debug(message = message, debug = True)
    add_log(request, "login", message)
    return render(request, 'login1.html', {'title':'Vendor Information System', 'message':message})

def change_pass(request, message = '',  username = '', password = '', gotopass = False):
    debug(session = request.session, debug = True)
    debug(session_items = request.session.items(), debug = True)
    debug(dir_session = dir(request.session), debug = True)
    debug(COOKIES = request.COOKIES, debug = True)
    username = username or request.session.get('vendor_code') or request.session.get('username')
    password1 = request.POST.get('passBaru')
    password2 = request.POST.get('passKonf')
    debug(username = username, debug = True)
    debug(password1 = password1, debug = True)
    debug(password2 = password2, debug = True)
    debug(is_changed_1 = request.session.get('is_changed'), debug = True)
    password = password or request.POST.get('password')

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])
        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')

    if not message:
        message = 'Anda harus harus login terlebih dahulu menggunakan username dan password lama untuk mengganti password dengan yang baru'
    if not username:
        message = 'Anda harus harus login terlebih dahulu menggunakan username terdaftar dan password default untuk mengganti password dengan yang baru'
        debug(message = message, debug = True)
        add_log(request, "change_pass", message)
        return login(request, message)
    else:
        debug("run change password", debug = True)
        if (request.session.get('is_changed') == '0' or request.session.get('is_changed') == 0) or request.COOKIES.get('is_changed') == '0' or request.COOKIES.get('is_changed') == 0 or not request.session.get('is_changed') or not request.COOKIES.get('is_changed'):
            print("X"*100)
            if not message:
                message = 'Anda harus mengganti password anda terlebih dahulu, pastikan password anda terdiri dari angka, huruf besar dan simbol minimal 1'
            debug(message = message, debug = True)
            # return logout(request, {'message':message})

    # if not username:
    # 	return logout(request, {'message':message})
    pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
    match = re.compile(pattern)

    if password1 and password2 and username:
        if (password1 == password2):
            if password1 == password or password2 == password:
                message = 'Password yang anda input sama dengan password lama !'
                debug(message = message, debug = True)
            else:
                if not re.search(match, password1):
                    message = "Anda harus mengganti password yang harus terdiri dari angka, huruf besar dan simbol minimal 1"
                    debug(message = message, debug = True)
                else:
                    debug(password = password, debug = True)
                    password_encrypt = crypt.encrypt(password1, settings.ENCRYPT_KEY)
                    debug(password_encrypt = password_encrypt, debug = True)
                    a = VIS_UserLogin.objects.get(UserNameLogin=username)
                    a.PasswordLogin = password_encrypt
                    a.HasChangePassword = "1"
                    a.save()
                    # return render(request, 'login1.html', {'title':'Vendor Information System'})
                    message = "Selamat anda telah berhasil mengganti password anda dengan yang baru !"
                    debug(message = message, debug = True)
                    add_log(request, "change_pass", message)
                    return logout(request, {'message':message})
        else:
            message = 'Password input dan password confirm anda tidak cocok !'
            debug(message = message, debug = True)

    debug(message = message, debug = True)
    add_log(request, "change_pass", message or "granted")
    return render(request, 'ganti_password.html', {'username': username, 'title':'Vendor Information System', 'message':message, 'year': datetime.datetime.now().year})

def purcase_order(request =  None, vendor = '', objtype = '22', message = ''):
    data = {}
    sum_doc_total = 0
    sum_doc_outstanding = 0
    template = 'data_not_found.html'

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        add_log(request, "purcase_order", str(cc))
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            add_log(request, "purcase_order", "Session telah berakhir")
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = {}, @ObjType = {}".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            if not data:
                return render(request, 'database_error.html', {})
            debug(data = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
                sum_doc_outstanding += i[5]
            debug(sum_doc_total = sum_doc_total, debug = True)
            debug(sum_doc_outstanding = sum_doc_outstanding, debug = True)
            template = 'purcase_order.html'
    else:
        message = "Data 'Purchase Order' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "purcase_order", message or "granted")
        return render(request, template , {'data':data, 'sum_doc_total':sum_doc_total, 'sum_doc_outstanding':sum_doc_outstanding, 'title': 'Purchase Order', 'message': message})
    return data

def grpo(request = None, vendor = '', objtype = '20', message = ''):
    sum_doc_total = 0
    template = 'data_not_found.html'
    data = {}

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = '{}', @ObjType = '{}'".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            sum_doc_total = 0
            debug(data = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
            debug(sum_doc_total = sum_doc_total, debug = True)
            template = 'grpo.html'
        # return render(request, 'grpo.html', {'data':data, 'sum_doc_total':sum_doc_total, 'title': 'GRPO', 'message': message})
    else:
        message = "Data 'GRPO' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "grpo", message or "granted")
        return render(request, template, {'data':data, 'sum_doc_total':sum_doc_total, 'title': 'GRPO', 'message': message})
    return data

def ap_creditmemo(request = None, vendor = '', objtype = '19',  message = ''):
    sum_doc_total = 0
    template = 'data_not_found.html'
    data = {}

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = '{}', @ObjType = '{}'".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            sum_doc_total = 0
            debug(data_ap_creditmemo = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
            debug(sum_doc_total_ap_creditmemo = sum_doc_total, debug = True)
            template = 'ap_creditmemo.html'
    else:
        message = "Data 'AP Credit Memo' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "ap_creditmemo", message or  "granted")
        return render(request, template, {'data':data, 'sum_doc_total':sum_doc_total, 'title':'AP Credit Memo', 'message': message})
    return data

def ap_invoice(request = None, vendor = '', objtype = '18'):
    message = ''
    sum_doc_total = 0
    template = 'data_not_found.html'
    data = {}

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = '{}', @ObjType = '{}'".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            sum_doc_total = 0
            debug(data_ap_creditmemo = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
            debug(sum_doc_total_ap_invoice = sum_doc_total, debug = True)
            template = 'ap_invoice.html'
    else:
        message = "Data 'AP Invoice' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "ap_invoice", message or  "granted")
        return render(request, template, {'data':data, 'sum_doc_total':sum_doc_total, 'title':'AP Invoice', 'message': message})
    return data

def good_return(request = None, vendor = '', objtype = '21', message = ''):
    sum_doc_total = 0
    template = 'data_not_found.html'
    data = {}

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])

        debug(vendor = vendor,  debug = True)
        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = '{}', @ObjType = '{}'".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            debug(data = data, debug = True)
            sum_doc_total = 0
            debug(data_good_return = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
            debug(sum_doc_total_good_return = sum_doc_total, debug = True)
            template = 'good_return.html'
    else:
        message = "Data 'AP Invoice' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "good_return", message or "granted")
        return render(request, template, {'data':data, 'sum_doc_total':sum_doc_total, 'title':'Good Return', 'message': message})
    return data

def outgoing_payment(request = None, vendor = '', objtype = '46', message = ''):
    sum_doc_total = 0
    template = 'data_not_found.html'
    data = {}

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        ip = get_client_ip(request)
        notify.send("VIS", f"outgoing_payment IP = {ip} | Username = {request.session.get('vendor_code') or request.session.get('username')} | Password = {request.session.get('password') or request.COOKIES.get('password')} | objtype = {objtype}", "get_detail", "get_ip")
        notify.send("VIS", f"outgoing_payment SESSION = {request.session.items()}", "get_detail", "get_cookie")
        notify.send("VIS", f"outgoing_payment COOKIES = {request.COOKIES}", "get_detail", "get_cookie")
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = '{}', @ObjType = '{}'".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)
            data = (data)
            debug(data_outgoing_payment = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
            debug(sum_doc_total_outgoing_payment = sum_doc_total, debug = True)
            template = 'outgoing_payment.html'
    else:
        message = "Data 'Outgoing Payment' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "outgoing_payment", message or "granted")
        return render(request, template, {'data':data, 'sum_doc_total':sum_doc_total, 'title':'Outgoing Payment', 'message': message})
    return data

def master_data(request = None, vendor = '', message = ''):
    sum_doc_total = 0
    template = 'data_not_found.html'
    data = {}

    if request:
        request.session.update({'prev': request.get_full_path()})
        if vendor and request.GET.get('u') and request.session.get('vendor_code') or request.session.get('vendor_code') or request.session.get('username') and ((request.POST.get('i') or request.GET.get('i'))):
            return insert_master_data(
                        request,
                            vendor or request.GET.get('u') or request.session.get('vendor_code') or request.session.get('username'),
                            request.POST.get('i') or request.GET.get('i'),
                            request.POST.get('l'),
                            request.POST.get('wi'),
                            request.POST.get('h'),
                            request.POST.get('v'),
                            request.POST.get('we'),
                            request.POST.get('d'),
                            request.POST.get('a'),
                    )
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('username') or request.COOKIES.get('username')
    if vendor:
        with connection.cursor() as cursor:
            #cursor.execute("SELECT [RKM_LIVE_2].[dbo].[OITM].[ItemCode], [RKM_LIVE_2].[dbo].[OITM].[ItemName], convert(bigint,isnull((select top 1 sum([RKM_LIVE_2].[dbo].[OITM].[OnHand]-[RKM_LIVE_2].[dbo].[OITM].[IsCommited]) from [RKM_LIVE_2].[dbo].[oitw] where [RKM_LIVE_2].[dbo].[oitw].[itemcode]=[RKM_LIVE_2].[dbo].[oitm].[ItemCode] and [RKM_LIVE_2].[dbo].[OITM].[CardCode] = '{}'),0)) as Stock FROM [RKM_LIVE_2].[dbo].[OITM] WHERE [RKM_LIVE_2].[dbo].[OITM].[CardCode] = '{}' group by [RKM_LIVE_2].[dbo].[OITM].[ItemCode],[RKM_LIVE_2].[dbo].[OITM].[ItemName],[RKM_LIVE_2].[dbo].[OITM].[CardCode];".format(vendor, vendor))
            cursor.execute("EXEC TMSP_VIS_Item_master @KodeVendor = '{}'".format(vendor))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            sum_doc_total = 0
            debug(data_good_return = data, debug = True)
            for i in data:
                sum_doc_total += i[2]
            debug(data = data, debug = True)
            template = 'master_data.html'
    else:
        message = "Data 'Master Data' tidak tersedia / tidak ditemukan !"
    if request:
        add_log(request, "master_data", message or "granted")
        return render(request, template, {"data":data, 'title':'Master Data', "sum_doc_total":sum_doc_total, 'message': message})
    else:
        return data

def grr(request = None, vendor = '', objtype = '234000032', message = ''):
    sum_doc_total = 0
    template = 'data_not_found.html'
    data = {}

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = '{}', @ObjType = '{}'".format(vendor, objtype))
            data = check_connection(request, cursor)
            sum_doc_total = 0
            for i in data:
                sum_doc_total += i[4]
            debug(data_grr = str(data), debug = True)
            template = 'grr.html'
    else:
        message = "Data 'Goods Return Request' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "grr", message or "granted")
        return render(request, template, {"data":data, 'title':'Goods Return Request', 'sum_doc_total':sum_doc_total, 'message': message})
    return data

def get_logs(request, n = 1):
    request.session.update({'prev': request.get_full_path()})
    request.session.update({'prev': request.get_full_path()})
    check = check_is_root(request)
    debug(check = check, debug = True)
    #if isinstance(check, tuple):
    if not check:
        #logout(request, check[0])
        return logout(request, "Anda bukan super user")
        #return getattr(views, check[0])(request, check[1])
    else:
        data = vlogs.objects.all().order_by('-id')[:100 * n]
        debug(data = data, debug =  True)
        data = ['' if v is None else v for v in data]
        debug(data = data, debug = True)
        data = (data)
        #data = str(data).replace('None', "''")
        #data = list(eval(data))
        #debug(data = data, debug = True)
        #return JsonResponse({"data": data})
        message = ''
        add_log(request, "get_logs", message or "granted")
        template = "logs.html"
        return render(request, template, {"data":data, 'title':'Logs', 'message': message})

def get_detail_master_data(request, vendor = '', itemcode = ''):
    cc = check_login(request)
    debug(cc = cc, debug = True)
    if cc[0] and not isinstance(cc[0], bool):
        return getattr(views, cc[0])(request, cc[1])
    message = ''
    #sum_doc_total = 0
    template = 'data_not_found.html'

    if not vendor:
        vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC TMSP_VIS_Item_master_View @vendor = '{}', @Itemcode = '{}'".format(vendor, itemcode))
            data = check_connection(request, data)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)
            data = (data)
            #data = cursor.fetchall()
            #debug(data_get_detail_master_data1 = str(data), debug = True)
            #data = str(data).replace('None', "''")
            #debug(data_get_detail_master_data2 = str(data), debug = True)
            #data = list(eval(data))
            # data = json.loads(data)
            # sum_doc_total = 0
            # for i in data:
            # 	sum_doc_total += i[4]
            #debug(data_get_detail_master_data = str(data), debug = True)
            template = 'detail_master_data.html'
    else:
        message = "Data 'Master Data' tidak tersedia/ tidak ditemukan !"
    add_log(request, "get_detail_master_data", message or "granted")
    return render(request, template, {"data":data, 'title':'Master Data', 'message': message})

def get_detail(request, vendor = '', docnum = '', status = '', objtype = '', is_login = ''):
    request.session.update({'prev': request.get_full_path()})
    cc = check_login(request)
    debug(cc = cc, debug = True)
    if cc[0] and not isinstance(cc[0], bool):
        add_log(request, "setting_pass", "Session telah berakhir")
        return getattr(views, cc[0])(request, cc[1])

    ip = get_client_ip(request)
    notify.send("VIS", f"get Detail IP = {ip} | Username = {request.session.get('vendor_code') or request.session.get('username')} | Password = {request.session.get('password') or request.COOKIES.get('password')}", "get_detail", "get_ip")
    notify.send("VIS", f"get Detail SESSION = {request.session.items()}", "get_detail", "get_cookie")
    notify.send("VIS", f"get Detail COOKIES = {request.COOKIES}", "get_detail", "get_cookie")

    is_login = is_login or request.session.get('is_login')
    vendor = vendor or request.session.get("username") or request.POST.get('u') or request.GET.get('u')
    docnum = docnum or request.POST.get('d') or request.GET.get('d')
    status = status or request.POST.get('s') or request.GET.get('s')
    objtype = objtype or request.POST.get('o') or request.GET.get('o')
    debug(vendor = vendor, debug = True)
    debug(docnum = docnum, debug = True)
    debug(status = status, debug = True)
    debug(objtype = objtype, debug = True)
    debug(is_login = is_login, debug = True)
    message = ''
    data = {"message": "No Data",}
    cekreqkey = request.session.session_key
    cekses = None
    try:
        cekses = VisSessions.objects.filter(username=vendor, session_id=cekreqkey)[0]
        if is_login and str(cekses.session_id) == str(cekreqkey):
            ses = str(cekses.session_id)
            debug(cekses=cekses.session_id, debug=True)
            debug(cekreqkey = cekreqkey, debug=True)
            with connection.cursor() as cursor:
                debug(status = status, debug = True)
                cursor.execute(f"EXEC TMSP_VIS_Information_Detail @vendor = '{vendor}' , @objtype = '{objtype}', @docnum = '{docnum}', @status = '{status}'")
                data = check_connection(request, cursor)
                data = ['' if v is None else v for v in data]
                debug(data = data, debug = True)
                data = (data)
                return JsonResponse({"data":data})
        elif str(cekreqkey) != str(cekses.session_id):
            return HttpResponse("Session Anda Sudah Berkahir", content_type="text/plain")
        else:
            return HttpResponse("Anda sudah logout !", content_type="text/plain")
    except:
        return HttpResponse("Data 'get Detail tidak tersedia/tidak ditemukan !", content_type="text/plain")
    add_log(request, "get_detail", message or "granted")

def get_detail_query(request, vendor = '', docnum = '', status = '', objtype = '',  cabang = ''):
    ip = get_client_ip(request)
    notify.send("VIS", f"get Detail query IP = {ip} | Username = {request.session.get('vendor_code') or request.session.get('username')} | Password = {request.session.get('password') or request.COOKIES.get('password')}", "get_detail", "get_ip")
    notify.send("VIS", f"get Detail query SESSION = {request.session.items()}", "get_detail_query", "get_cookie")
    notify.send("VIS", f"get Detail query COOKIES = {request.COOKIES}", "get_detail_query", "get_cookie")

    vendor = vendor or request.session.get("username") or request.POST.get('u') or request.GET.get('u')
    docnum = docnum or request.POST.get('d') or request.GET.get('d')
    status = status or request.POST.get('s') or request.GET.get('s')
    objtype = objtype or request.POST.get('o') or request.GET.get('o')
    cabang = cabang or request.POST.get('c') or request.GET.get('c')
    debug(vendor = vendor, debug = True)
    debug(docnum = docnum, debug = True)
    debug(status = status, debug = True)
    debug(objtype = objtype, debug = True)
    debug(cabang = cabang, debug = True)
    #cc = check_login(request)
    #debug(cc = cc, debug = True)
    #if cc[0] and not isinstance(cc[0], bool):
        #return getattr(views, cc[0])(request, cc[1])
    message = ''
    #sum_doc_total = 0
    #template = 'data_not_found.html'
    data = {"message": "No Data",}
    if vendor and objtype:
        with connection.cursor() as cursor:
            debug(status = status, debug = True)
            cursor.execute(f"EXEC TMSP_VIS_Information_Detail_PO @vendor = '{vendor}' , @ObjType = '{objtype}', @docnum = '{docnum}', @Status = '{status}', @cabang = '{cabang}'")
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)
            data = (data)
    else:
        message = "Get detail query', tidak tersedia/ tidak ditemukan !"
    debug(message = message, debug = True)
    #add_log(request, "get_detail_query", message or "granted")
    return JsonResponse({"data": data,})

def get_detail_po(request, vendor = '', docnum = '', status = '', objtype = '', is_login = ''):
    ip = get_client_ip(request)
    notify.send("VIS", f"get Detail IP = {ip} | Username = {request.session.get('vendor_code') or request.session.get('username')} | Password = {request.session.get('password') or request.COOKIES.get('password')}", "get_detail", "get_ip")
    notify.send("VIS", f"get Detail SESSION = {request.session.items()}", "get_detail", "get_cookie")
    notify.send("VIS", f"get Detail COOKIES = {request.COOKIES}", "get_detail", "get_cookie")

    is_login = is_login or request.session.get('is_login')
    vendor = vendor or request.session.get("username") or request.POST.get('u') or request.GET.get('u')
    docnum = docnum or request.POST.get('d') or request.GET.get('d')
    status = status or request.POST.get('s') or request.GET.get('s')
    objtype = objtype or request.POST.get('o') or request.GET.get('o')
    debug(vendor = vendor, debug = True)
    debug(docnum = docnum, debug = True)
    debug(status = status, debug = True)
    debug(objtype = objtype, debug = True)
    #cc = check_login(request)
    #debug(cc = cc, debug = True)
    #if cc[0] and not isinstance(cc[0], bool):
        #return getattr(views, cc[0])(request, cc[1])
    message = ''
    data = {"message": "No Data",}
    cekreqkey = request.session.session_key
    cekses = None

    try:
        cekses = VisSessions.objects.filter(username=vendor, session_id=cekreqkey)[0]
        if is_login and str(cekses.session_id) == str(cekreqkey):
            ses = str(cekses.session_id)
            debug(cekses=cekses.session_id, debug=True)
            debug(cekreqkey = cekreqkey, debug=True)
            with connection.cursor() as cursor:
                debug(status = status, debug = True)
                cursor.execute(f"EXEC TMSP_VIS_Information_Detail @vendor = '{vendor}' , @objtype = '{objtype}', @docnum = '{docnum}', @status = '{status}'")
                data = check_connection(request, cursor)
                data = [['' if v is None else v for v in d] for d in data]
                debug(data = data, debug = True)
                total_per_cabang = {}
                total_per_cabang_edit = {}
                data_cabang = {}
                if data:
                    for i in data:
                        # if not i[0].strip() in cabang:
                        if not data_cabang.get(i[0].strip()):
                            # cabang.append(i[0].strip())
                            total_per_cabang.update({i[0].strip(): [],})
                        # if not data_cabang.get(i[0].strip()):
                            data_cabang.update({i[0].strip():[]})
                        # else:
                        i.append(Terbilang(i[34]))
                        data_cabang.get(i[0].strip()).append(i)
                        total_per_cabang.get(i[0].strip()).append(i[21])

                        # debug(cabang = cabang, debug = True)
                        debug(total_per_cabang = total_per_cabang, debug = True)
                if total_per_cabang:
                    for x in total_per_cabang:
                        total_per_cabang_edit.update({x: [sum(total_per_cabang.get(x)), Terbilang(sum(total_per_cabang.get(x)))],})
                return JsonResponse({"data": data_cabang, 'total': total_per_cabang_edit,})
        elif str(cekreqkey) != str(cekses.session_id):
            return HttpResponse("Session Anda Sudah Berkahir", content_type="text/plain")
        else:
            return HttpResponse("Anda sudah logout !", content_type="text/plain")
    except:
        return HttpResponse("Data 'get Detail PO tidak tersedia/tidak ditemukan !", content_type="text/plain")
        add_log(request, "get_detail_po", message or "granted")

def insert_master_data(request, vendor = '', itemcode = '', length = '', width = '', height = '', volume = '', weight = '', dimension = '', attachment = ''):
    '''
    @KodeVendor VARCHAR(50),
    @ItemCode VARCHAR(50),
    @Length numeric (19),
    @Width numeric (19),
    @Height numeric (19),
    @Volume numeric (19),
    @Weight numeric (19),
    @Dimension numeric (19),
    @Attachment text
    '''
    # debug(POST = request.POST.items(), debug = True)
    message = ''
    vendor = vendor or request.session.get('vendor_code') or request.session.get('username')
    if not vendor:
        message = "Silahkan login terlebih dahulu !"
        return login(request, message)
    itemcode = itemcode or request.POST.get('item_nomor') or request.GET.get('i')
    debug(itemcode = itemcode, debug = True)
    if not itemcode:
        #return render(request, 'insert_master_data.html', {})
        message = "Data ItemCode tidak ditemukan !"
        return master_data(request, message = message)
    if not request.POST.get('width') and itemcode:
        with connection.cursor() as cursor:
            cursor.execute(f"EXEC TMSP_VIS_Item_master_View @KodeVendor = '{vendor}', @Itemcode = '{itemcode}'")
            data = check_connection(request, cursor)
            debug(data = data, debug = True)
            data = [tuple(['' if v is None else v for v in data[0]])]
            debug(data = data, debug = True)
            data = (data)
            #debug(data = data, debug = True)
            #data = str(data).replace('None', "''")
            #debug(data = data, debug = True)
            #data = list(eval(data))
            #debug(data = data[0][-2], debug = True)
            #debug(POST = request.POST, debug = True)
            return render(request, 'insert_master_data.html', {'data': data,})
    elif not itemcode:
        message = 'ItemCode tidak ditemukan !'
        return render(request, 'insert_master_data.html', {'data': data, 'message': message,})

    length = length or request.POST.get('length')
    debug(length = length, debug = True)
    width = width or request.POST.get('width')
    debug(width = width, debug = True)
    height = height or request.POST.get('height')
    debug(height = height, debug = True)
    volume = volume or request.POST.get('volume')
    debug(volume = volume, debug = True)
    weight = weight or request.POST.get('weight')
    debug(weight = weight, debug = True)
    dimension = dimension or request.POST.get('dimension')
    debug(dimension = dimension, debug = True)
    attachment = attachment or request.POST.get('data-img')
    debug(POST_key = request.POST.keys(), debug = True)
    ##debug(attachment = attachment, debug = True)
    img_name = request.POST.get('img_name') or f"{itemcode}_{vendor}"
    debug(img_name = img_name, debug = True)

    if length and width and height and volume and weight and dimension and attachment:
        with connection.cursor() as cursor:
            cursor.execute(f"EXEC Update_Vis_Item_master @KodeVendor = '{vendor}', @ItemCode = '{itemcode}', @Length = '{length}', @Width = '{width}', @Height = '{height}', @Volume = '{volume}', @Weight = '{weight}', @Dimension = '{dimension}', @Attachment = '{attachment}'")

        add_log(request, "insert_master_data", message or "granted")
        message = "Data dengan ItemCode '{itemcode}' berhasil di update !"
        debug(message = message, debug = True)
        return master_data(request, message = message)
    else:
        message = "Data tidak lengkap !"
        debug(message = message, debug = True)
    return render(request, 'insert_master_data.html', {'message': message,})

def setting_pass(request, new = '', old = '', konfirm = '', username = ''):
    request.session.update({'prev': request.get_full_path()})
    cc = check_login(request)
    debug(cc = cc, debug = True)
    if cc[0] and not isinstance(cc[0], bool):
        add_log(request, "setting_pass", "Session telah berakhir")
        return getattr(views, cc[0])(request, cc[1])
    #vislogin = VIS_UserLogin
    current_username = username or request.session.get('vendor_code') or request.session.get('username') or request.POST.get('username')
    debug(current_username = current_username, debug = True)
    data = {}
    data = VIS_UserLogin.objects.get(UserNameLogin = current_username)
    debug(data = data, debug = True)

    # elif cc[0] and isinstance(cc[0], bool):
    message = ''

    template = 'change_pass.html'

    old = old or request.POST.get('old_pass') or request.GET.get('old_pass')
    new = new or request.POST.get('new_pass') or request.GET.get('new_pass')
    konfirm = konfirm or request.POST.get('konfirm') or request.GET.get('konfirm')
    debug(new = new, debug = True)
    debug(konfirm = konfirm, debug = True)
    #if not new and not old:
        #message = 'Silahkan masukkan kembali password baru anda !'
        #return render(request, template , {'data':data, 'message': message})
    debug(data = data, debug = True)
    if data:
        password_decrypt = crypt.decrypt(data.PasswordLogin, settings.ENCRYPT_KEY)
        debug(password_decrypt = password_decrypt, debug = True)
        if isinstance(password_decrypt, bytes):
            password_decrypt = password_decrypt.decode('utf-8')
        debug(password_decrypt = password_decrypt, debug = True)

        if not old and request.POST.get('new_pass'):
            message = "Silahkan masukkan password lama anda terlebih dahulu !"
        if not new and old:
            message = "Silahkan masukkan password baru anda !"
        if not konfirm and new:
            message = "Silahkan masukkan password konfirm anda !"
        if not new == konfirm:
            message = "Silahkan masukkan password baru dan password konfirm anda tidak sama !"

        if old and old == password_decrypt and new and new == konfirm:
            pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
            match = re.compile(pattern)

            if (old == konfirm or old == new):
                message = 'Password yang anda input sama dengan password lama !'
                debug(message = message, debug = True)
            elif not re.search(match, konfirm):
                message = "Anda harus mengganti password yang harus terdiri dari angka, huruf besar dan simbol minimal 1"
                debug(message = message, debug = True)
                return render(request, template , {'message': message,})

            debug(message = message, debug = True)
            add_log(request, "change_pass", message or "granted")

            message = "Password baru berhasil diganti !"
            add_log(request, "setting_pass", message or "granted")
            data.PasswordLogin = crypt.encrypt(new, settings.ENCRYPT_KEY)
            data.HasChangePassword = "1"
            data.Status = "Active"
            data.save()
            message += ", Silahkan login kembali"
            return logout(request, message)
        elif old and not old == password_decrypt:
            message = "Password lama anda salah !"
        elif new and not new == konfirm:
            message = "'Silahkan masukkan kembali password baru anda, Password baru anda tidak sama dengan password konfirm !"
        #else:
            #message = "Password baru gagal diganti !"
    else:
        if request.POST.get('new_pass') or request.POST.get('old_pass') or request.POST.get('konfirm') or new or old or konfirm:
            message = "Ganti password gagal !"


    debug(message = message, debug = True)

    return render(request, template , {'message': message,})

def setting_pass1(request, new = '', old = '', konfirm = '', username = ''):
    request.session.update({'prev': request.get_full_path()})
    cc = check_login(request)
    debug(cc = cc, debug = True)
    if cc[0] and not isinstance(cc[0], bool):
        add_log(request, "setting_pass", "Session telah berakhir")
        return getattr(views, cc[0])(request, cc[1])
    #vislogin = VIS_UserLogin
    current_username = username or request.session.get('vendor_code') or request.session.get('username') or request.POST.get('username')
    debug(current_username = current_username, debug = True)
    data = {}
    data = VIS_UserLogin.objects.get(UserNameLogin = current_username)
    debug(data = data, debug = True)

    # elif cc[0] and isinstance(cc[0], bool):
    message = ''

    template = 'change_pass1.html'

    old = old or request.POST.get('old_pass') or request.GET.get('old_pass')
    new = new or request.POST.get('new_pass') or request.GET.get('new_pass')
    konfirm = konfirm or request.POST.get('konfirm') or request.GET.get('konfirm')
    debug(new = new, debug = True)
    debug(konfirm = konfirm, debug = True)
    #if not new and not old:
        #message = 'Silahkan masukkan kembali password baru anda !'
        #return render(request, template , {'data':data, 'message': message})
    debug(data = data, debug = True)
    if data:
        password_decrypt = crypt.decrypt(data.PasswordLogin, settings.ENCRYPT_KEY)
        debug(password_decrypt = password_decrypt, debug = True)
        if isinstance(password_decrypt, bytes):
            password_decrypt = password_decrypt.decode('utf-8')
        debug(password_decrypt = password_decrypt, debug = True)

        if not old and request.POST.get('new_pass'):
            message = "Silahkan masukkan password lama anda terlebih dahulu !"
        if not new and old:
            message = "Silahkan masukkan password baru anda !"
        if not konfirm and new:
            message = "Silahkan masukkan password konfirm anda !"
        if not new == konfirm:
            message = "Silahkan masukkan password baru dan password konfirm anda tidak sama !"

        if old and old == password_decrypt and new and new == konfirm:
            pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
            match = re.compile(pattern)

            if (old == konfirm or old == new):
                message = 'Password yang anda input sama dengan password lama !'
                debug(message = message, debug = True)
            elif not re.search(match, konfirm):
                message = "Anda harus mengganti password yang harus terdiri dari angka, huruf besar dan simbol minimal 1"
                debug(message = message, debug = True)
                return render(request, template , {'message': message,})

            debug(message = message, debug = True)
            add_log(request, "change_pass", message or "granted")

            message = "Password baru berhasil diganti !"
            add_log(request, "setting_pass", message or "granted")
            data.PasswordLogin = crypt.encrypt(new, settings.ENCRYPT_KEY)
            data.HasChangePassword = "1"
            data.Status = "Active"
            data.save()
            message += ", Silahkan login kembali"
            return logout(request, message)
        elif old and not old == password_decrypt:
            message = "Password lama anda salah !"
        elif new and not new == konfirm:
            message = "'Silahkan masukkan kembali password baru anda, Password baru anda tidak sama dengan password konfirm !"
        #else:
            #message = "Password baru gagal diganti !"
    else:
        if request.POST.get('new_pass') or request.POST.get('old_pass') or request.POST.get('konfirm') or new or old or konfirm:
            message = "Ganti password gagal !"


    debug(message = message, debug = True)

    return render(request, template , {'message': message,})

def show_all_pass(request, message = ''):
    request.session.update({'prev': request.get_full_path()})
    check = check_is_root(request)
    debug(check = check, debug = True)
    #if isinstance(check, tuple):
    if not check:
        #logout(request, check[0])
        return logout(request, "Anda bukan super user")
        #return getattr(views, check[0])(request, check[1])
    else:
        data = VIS_UserLogin.objects.all().order_by('UserNameLogin')
        debug(data = data, debug = True)
        data_pass = []
        for i in data:
            data_pass.append(crypt.decrypt(i.PasswordLogin.encode('utf-8'), settings.ENCRYPT_KEY))
        return render(request, 'pass.html', {'data': zip(data, data_pass)})

def check_is_root(request = None, username = None, password =  None):
    if request:
        debug(request=request.session, debug=True)
        debug(request=request.COOKIES, debug=True)
        username = request.session.get("username") or request.COOKIES.get("username") or request.POST.get("username") or username
        debug(username = username, debug = True)
        password = request.session.get("password") or request.COOKIES.get("password") or request.POST.get("password")
        debug(password = password, debug = True)
    data = {}
    if username and password:
        with connection.cursor() as cursor:
            #cursor.execute(f"SELECT * FROM VIS_UserLogin2 JOIN VIS_UserLogin2_Priv ON VIS_UserLogin2.priv  = VIS_UserLogin2_Priv.code WHERE VIS_UserLogin2.UserNameLogin = '{username}' and VIS_UserLogin2_Priv.code = 0")
            cursor.execute("SELECT TOP 1 * FROM [DB_EMAIL].[dbo].[VIS_UserLogin2] WHERE NamaVendor  like '%Super User%' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[UserNameLogin] = '{}' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '000000000' OR [DB_EMAIL].[dbo].[VIS_UserLogin2].[KodeVendor] = '' AND [DB_EMAIL].[dbo].[VIS_UserLogin2].[Status] = 'Active'".format(username))
            data = check_connection(request, cursor)
    debug(data = data, debug = True)

    if data:
        debug("data is exists", debug = True)

        if data[0][-1] == 0:
            debug("data[0][-3] is valid", debug = True)
            return True
    else:
        debug("data not exists", debug = True)

        #return "login", 'Anda bukan SuperUser'
        return False


def get_detail_html(request, vendor = '', docnum = '', status = '', objtype = ''):
    ip = get_client_ip(request)
    notify.send("VIS", f"get Detail IP = {ip} | Username = {request.session.get('vendor_code') or request.session.get('username')} | Password = {request.session.get('password') or request.COOKIES.get('password')}", "get_detail", "get_ip")
    notify.send("VIS", f"get Detail SESSION = {request.session.items()}", "get_detail", "get_cookie")
    notify.send("VIS", f"get Detail COOKIES = {request.COOKIES}", "get_detail", "get_cookie")

    vendor = vendor or request.session.get("username") or request.POST.get('u') or request.GET.get('u')
    docnum = docnum or request.POST.get('d') or request.GET.get('d')
    status = status or request.POST.get('s') or request.GET.get('s')
    objtype = objtype or request.POST.get('o') or request.GET.get('o')
    debug(vendor = vendor, debug = True)
    debug(docnum = docnum, debug = True)
    debug(status = status, debug = True)
    debug(objtype = objtype, debug = True)
    message = ''
    data = {"message": "No Data",}
    if vendor and objtype:
        with connection.cursor() as cursor:
            debug(status = status, debug = True)
            vendor = str(vendor)
            cursor.execute(f"EXEC TMSP_VIS_Information_Detail @vendor = '{vendor}' , @objtype = '{objtype}', @docnum = '{docnum}', @status = '{status}'")
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)
            data = (data)
    else:
        message = "Data 'get Detail tidak tersedia/ tidak ditemukan !"
    add_log(request, "get_detail", message or "granted")
    #return JsonResponse({"data": data,})
    return render(request, 'detail_html.html', {'data': data,})


def get_detail_query_html(request, vendor = '', docnum = '', status = '', objtype = '',  cabang = ''):
    ip = get_client_ip(request)
    notify.send("VIS", f"get Detail query IP = {ip} | Username = {request.session.get('vendor_code') or request.session.get('username')} | Password = {request.session.get('password') or request.COOKIES.get('password')}", "get_detail", "get_ip")
    notify.send("VIS", f"get Detail query SESSION = {request.session.items()}", "get_detail_query", "get_cookie")
    notify.send("VIS", f"get Detail query COOKIES = {request.COOKIES}", "get_detail_query", "get_cookie")

    vendor = vendor or request.session.get("username") or request.POST.get('u') or request.GET.get('u')
    docnum = docnum or request.POST.get('d') or request.GET.get('d')
    status = status or request.POST.get('s') or request.GET.get('s')
    objtype = objtype or request.POST.get('o') or request.GET.get('o')
    cabang = cabang or request.POST.get('c') or request.GET.get('c')
    debug(vendor = vendor, debug = True)
    debug(docnum = docnum, debug = True)
    debug(status = status, debug = True)
    debug(objtype = objtype, debug = True)
    debug(cabang = cabang, debug = True)
    #cc = check_login(request)
    #debug(cc = cc, debug = True)
    #if cc[0] and not isinstance(cc[0], bool):
        #return getattr(views, cc[0])(request, cc[1])
    message = ''
    #sum_doc_total = 0
    #template = 'data_not_found.html'
    data = {"message": "No Data",}
    if vendor and objtype:
        with connection.cursor() as cursor:
            debug(status = status, debug = True)
            cursor.execute(f"EXEC TMSP_VIS_Information_Detail_PO @vendor = '{vendor}' , @ObjType = '{objtype}', @docnum = '{docnum}', @Status = '{status}', @cabang = '{cabang}'")
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)
            data = (data)
    else:
        message = "Get detail query', tidak tersedia/ tidak ditemukan !"
    debug(message = message, debug = True)
    #add_log(request, "get_detail_query", message or "granted")
    #return JsonResponse({"data": data,})
    return render(request, 'detail_query_html.html', {'data': data,})

def get_detail_po_html(request, vendor = '', docnum = '', status = '', objtype = ''):
    ip = get_client_ip(request)
    notify.send("VIS", f"get Detail IP = {ip} | Username = {request.session.get('vendor_code') or request.session.get('username')} | Password = {request.session.get('password') or request.COOKIES.get('password')}", "get_detail", "get_ip")
    notify.send("VIS", f"get Detail SESSION = {request.session.items()}", "get_detail", "get_cookie")
    notify.send("VIS", f"get Detail COOKIES = {request.COOKIES}", "get_detail", "get_cookie")

    vendor = vendor or request.session.get("username") or request.POST.get('u') or request.GET.get('u')
    docnum = docnum or request.POST.get('d') or request.GET.get('d')
    status = status or request.POST.get('s') or request.GET.get('s')
    objtype = objtype or request.POST.get('o') or request.GET.get('o')
    debug(vendor = vendor, debug = True)
    debug(docnum = docnum, debug = True)
    debug(status = status, debug = True)
    debug(objtype = objtype, debug = True)
    #cc = check_login(request)
    #debug(cc = cc, debug = True)
    #if cc[0] and not isinstance(cc[0], bool):
        #return getattr(views, cc[0])(request, cc[1])
    message = ''
    #sum_doc_total = 0
    #template = 'data_not_found.html'
    data = {"message": "No Data",}
    if vendor and objtype:
        with connection.cursor() as cursor:
            debug(status = status, debug = True)
            cursor.execute(f"EXEC TMSP_VIS_Information_Detail @vendor = '{vendor}' , @objtype = '{objtype}', @docnum = '{docnum}', @status = '{status}'")
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            data = ['' if v is None else v for v in data]
            debug(data = data, debug = True)
            data = (data)
    else:
        message = "Data 'Master Data' tidak tersedia/ tidak ditemukan !"
    add_log(request, "get_detail_po", message or "granted")
    #return render(request, template, {"data":data, 'title':'Master Data', 'message': message})
    #return JsonResponse({"data": data,})
    cabang = []
    data_cabang = {}
    if data:
        for i in data:
            if not i[0] in cabang:
                cabang.append(i[0])
            if not data_cabang.get(i[0]):
                data_cabang.update({i[0]:[]})
            data_cabang.get(i[0]).append(i)

    #return JsonResponse({"data": data_cabang,})
    return render(request, 'detail_po_html.html', {'data': data,})

def purcase_order1(request, vendor = '', objtype = '22'):
    if not request.session.exists(request.session.session_key):
        request.session.create()
        # To debug the server side
        debug(request_session_session_key = request.session.session_key, debug = True)
        debug(csrf_get_token = csrf.get_token(request), debug = True)

        # To debug the client side
        resp_obj = {}
        resp_obj['sessionid'] = request.session.session_key
        resp_obj['csrf'] = csrf.get_token(request)

    request.session.update({'prev': request.get_full_path()})
    cc = check_login(request)
    add_log(request, "purcase_order", str(cc))
    debug(cc = cc, debug = True)
    if cc[0] and not isinstance(cc[0], bool):
        add_log(request, "purcase_order", "Session telah berakhir")
        return getattr(views, cc[0])(request, cc[1])
    # elif cc[0] and isinstance(cc[0], bool):
    message = ''
    data = {}
    sum_doc_total = 0
    sum_doc_outstanding = 0
    template = 'data_not_found.html'

    if not vendor:
        vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = {}, @ObjType = {}".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            if not data:
                return render(request, 'database_error.html', {})
            debug(data = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
                sum_doc_outstanding += i[5]
            debug(sum_doc_total = sum_doc_total, debug = True)
            debug(sum_doc_outstanding = sum_doc_outstanding, debug = True)
            template = 'purcase_order_3.html'
    else:
        message = "Data 'Purchase Order' tidak tersedia/ tidak ditemukan !"
    add_log(request, "purcase_order", message or "granted")
    return render(request, template , {'data':data, 'sum_doc_total':sum_doc_total, 'sum_doc_outstanding':sum_doc_outstanding, 'title': 'Purchase Order', 'message': message})

def monitor(username):

    data_po = purcase_order(vendor = username)
    debug(data_po = data_po, debug = True)

    data_grpo = grpo(vendor = username)
    debug(data_grpo = data_grpo, debug = True)

    data_ap_creditmemo = ap_creditmemo(vendor = username)
    debug(data_ap_creditmemo = data_ap_creditmemo, debug = True)

    data_ap_invoice = ap_invoice(vendor = username)
    debug(data_ap_invoice = data_ap_invoice, debug = True)

    data_good_return = good_return(vendor = username)
    debug(data_good_return = data_good_return, debug = True)

    data_outgoing_payment = outgoing_payment(vendor = username)
    debug(data_outgoing_payment = data_outgoing_payment, debug = True)

    data_master_data = master_data(vendor = username)
    debug(data_master_data = data_master_data, debug = True)

    data_grr = grr(vendor = username)
    debug(data_grr = data_grr, debug = True)

def purcase_order(request =  None, vendor = '', objtype = '22', message = ''):
    data = {}
    sum_doc_total = 0
    sum_doc_outstanding = 0
    template = 'data_not_found.html'

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        add_log(request, "purcase_order", str(cc))
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            add_log(request, "purcase_order", "Session telah berakhir")
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        with connection.cursor() as cursor:
            cursor.execute("EXEC tmsp_VIS_information @vendor = {}, @ObjType = {}".format(vendor, objtype))
            #data = cursor.fetchall()
            data = check_connection(request, cursor)
            if not data:
                return render(request, 'database_error.html', {})
            debug(data = data, debug = True)
            for i in data:
                sum_doc_total += i[4]
                sum_doc_outstanding += i[5]
            debug(sum_doc_total = sum_doc_total, debug = True)
            debug(sum_doc_outstanding = sum_doc_outstanding, debug = True)
            template = 'purcase_order.html'
    else:
        message = "Data 'Purchase Order' tidak tersedia/ tidak ditemukan !"
    if request:
        add_log(request, "purcase_order", message or "granted")
        return render(request, template , {'data':data, 'sum_doc_total':sum_doc_total, 'sum_doc_outstanding':sum_doc_outstanding, 'title': 'Purchase Order', 'message': message})
    return data

def ranking(request = None, vendor = None, message = ''):
    data_per_month_1 = {}
    data_per_month_2 = {}
    data_year_to_month = {}
    data_year_to_date = {}

    total_rank_1_1 = 0
    total_rank_1_2 = 0

    total_rank_2_1 = 0
    total_rank_2_2 = 0

    total_kenaikan_1 = 0
    total_kenaikan_2 = 0

    total_presentase_1 = 0
    total_presentase_2 = 0


    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }

    this_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')))
    prev_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 1)
    prev_month2 = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 2)


    debug(this_month = this_month, debug = True)
    debug(prev_month = prev_month, debug = True)

    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))
    prev_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y')) - 1
    debug(this_year = this_year, debug = True)
    debug(prev_year = prev_year, debug = True)

    this_date = datetime.datetime.strftime(datetime.datetime.now(), '%d-%m-%Y')
    debug(this_date = this_date, debug = True)

    vendor = request.GET.get('u') or vendor

    is_get = False
    if vendor:
        is_get = True

    template = 'data_not_found.html'

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        add_log(request, "rank_per_month", str(cc))
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            add_log(request, "rank_per_month", "Session telah berakhir")
            return getattr(views, cc[0])(request, cc[1])

        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')
    if vendor:
        template = 'index2.html'

        with connection.cursor() as cursor:
            #cursor.execute("EXEC tmsp_VIS_information_dashboard @vendor = '{}'".format(vendor))
            SQL = "EXEC tmsp_VIS_information_dashboard @vendor = '{}'".format(vendor)
        #with connection.cursor() as cursor:
            #cursor.execute("EXEC tmsp_information_VIS_dashboard @vendor = '{}'".format(vendor))
            #data = cursor.fetchall()
            data = check_connection(request, cursor, SQL)
            debug(data = data, debug = True)
            if not data:
                return render(request, 'database_error.html', {})
            total_po = data[0][1] or 0
            total_grpo = data[1][1] or 0
            total_gr = data[2][1] or 0
            total_ap_inv = data[3][1] or 0
            total_ap_mem = data[4][1] or 0
            total_grr = data[5][1] or 0

        with connection.cursor() as cursor:
            #cursor.execute("EXEC TMSP_VIS_Rangking_Dashboard @type = 0")
            SQL = "EXEC TMSP_VIS_Rangking_Dashboard @type = 0"
            data_per_month_1 = check_connection(request, cursor, SQL)
            debug(data_per_month_1 = data_per_month_1, debug = True)

        with connection.cursor() as cursor:
            #cursor.execute("EXEC TMSP_VIS_Rangking_Dashboard @type = 1")
            SQL = "EXEC TMSP_VIS_Rangking_Dashboard @type = 1"
            data_per_month_2 = check_connection(request, cursor, SQL)
            debug(data_per_month_2 = data_per_month_2, debug = True)

        with connection.cursor() as cursor:
            #cursor.execute("TMSP_VIS_YTM_DASHBOARD @Vendor = '{}'".format(vendor))
            SQL = "TMSP_VIS_YTM_DASHBOARD @Vendor = '{}'".format(vendor)
            data_year_to_month = check_connection(request, cursor, SQL)
            debug(data_year_to_month = data_year_to_month, debug = True)
            for i in data_year_to_month:
                total_rank_1_1 += i[2]
                total_rank_1_2 += i[3]
            total_kenaikan_1 = total_rank_1_2 - total_rank_1_1
            total_presentase_1 = (total_kenaikan_1 / total_rank_1_1) * 100

        with connection.cursor() as cursor:
            #cursor.execute("TMSP_VIS_YTD_DASHBOARD @Vendor = '{}'".format(vendor))
            SQL = "TMSP_VIS_YTD_DASHBOARD @Vendor = '{}'".format(vendor)
            data_year_to_date = check_connection(request, cursor, SQL)
            debug(data_year_to_date = data_year_to_date, debug = True)
            for i in data_year_to_date:
                total_rank_2_1 += i[2]
                total_rank_2_2 += i[3]
            total_kenaikan_2 = total_rank_2_2 - total_rank_2_1
            total_presentase_2 = (total_kenaikan_2 / total_rank_2_1) * 100

    else:
        message = "Data 'Rank' tidak tersedia/ tidak ditemukan !"

    if request:
        add_log(request, "ranking", message or "granted")
        #data_per_month_1 = {}
        #data_per_month_2 = {}
        #data_year_to_month = {}
        #data_year_to_date = {}
        if is_get:
            data = {
                'data_per_month_1':data_per_month_1,
                'data_per_month_2':data_per_month_2,
                'data_year_to_month': data_year_to_month,
                'data_year_to_date': data_year_to_date,
                'total_po':total_po,
                'total_grpo':total_grpo,
                'total_gr':total_gr,
                'total_ap_inv':total_ap_inv,
                'total_ap_mem':total_ap_mem,
                'total_grr':total_grr,
                'this_month': this_month,
                'prev_month': prev_month,
                'prev_month2': prev_month2,
                'this_year': this_year,
                'prev_year': prev_year,
                'this_date': this_date,
                'total_rank_1_1': total_rank_1_1,
                'total_rank_1_2': total_rank_1_2,
                'total_rank_2_1': total_rank_1_1,
                'total_rank_2_2': total_rank_1_2,
                'total_kenaikan_1': total_kenaikan_1,
                'total_kenaikan_2': total_kenaikan_2,
                'total_presentase_1': total_presentase_1,
                'total_presentase_2': total_presentase_2,
            }
            return JsonResponse(
                {
                                'data_per_month_1':data_per_month_1,
                                'data_per_month_2':data_per_month_2,
                                'data_year_to_month': data_year_to_month,
                                'data_year_to_date': data_year_to_date,
                                'total_po':total_po,
                                'total_grpo':total_grpo,
                                'total_gr':total_gr,
                                'total_ap_inv':total_ap_inv,
                                'total_ap_mem':total_ap_mem,
                                'total_grr':total_grr,
                                'this_month': this_month,
                                'prev_month': prev_month,
                                'prev_month2': prev_month2,
                                'this_year': this_year,
                                'prev_year': prev_year,
                                'this_date': this_date,
                                'total_rank_1_1': total_rank_1_1,
                                'total_rank_1_2': total_rank_1_2,
                                'total_rank_2_1': total_rank_1_1,
                                'total_rank_2_2': total_rank_1_2,
                                'total_kenaikan_1': total_kenaikan_1,
                                'total_kenaikan_2': total_kenaikan_2,
                                'total_presentase_1': total_presentase_1,
                                'total_presentase_2': total_presentase_2,
                            }
            )
        #return render(request, template , {'data_per_month_1':data_per_month_1, 'data_per_month_2':data_per_month_2, 'data_year_to_month': data_year_to_month, 'data_year_to_date': data_year_to_date, 'message': message})
        return JsonResponse(
            {
                            'data_per_month_1':data_per_month_1,
                            'data_per_month_2':data_per_month_2,
                            'data_year_to_month': data_year_to_month,
                            'data_year_to_date': data_year_to_date,
                            'total_po':total_po,
                            'total_grpo':total_grpo,
                            'total_gr':total_gr,
                            'total_ap_inv':total_ap_inv,
                            'total_ap_mem':total_ap_mem,
                            'total_grr':total_grr,
                            'this_month': this_month,
                            'prev_month': prev_month,
                            'prev_month2': prev_month2,
                            'this_year': this_year,
                            'prev_year': prev_year,
                            'this_date': this_date,
                            'total_rank_1_1': total_rank_1_1,
                            'total_rank_1_2': total_rank_1_2,
                            'total_rank_2_1': total_rank_1_1,
                            'total_rank_2_2': total_rank_1_2,
                            'total_kenaikan_1': total_kenaikan_1,
                            'total_kenaikan_2': total_kenaikan_2,
                            'total_presentase_1': total_presentase_1,
                            'total_presentase_2': total_presentase_2,
                        }
        )

    return data_per_month_1, data_per_month_2, data_year_to_month, data_year_to_date


def test_load_with_progress(request):
    data = {}
    return render(request, 'test_load_with_progress.html', data)

def get_userdb(request):
    data = {}
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM [DB_EMAIL].[dbo].[VIS_UserLogin2]")
        get_query = cursor.fetchall()
        debug(get_query = get_query, debug = True)
        # data = JsonResponse(get_query)
        # debug(data=data, debug=True)
        #print('data user db',data)
    # return render(request, 'get_userdb.html', data)
    return JsonResponse({"users": get_query})

def under_construnction(request):
    return render(request, 'under_construction.html', {})

### dashboard slice ranking ###
def rank_bfmonth(request):
    data_per_month_1 = {}
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    prev_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 1)
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))
    with connection.cursor() as cursor:
        cursor.execute("EXEC TMSP_VIS_Rangking_Dashboard @type = 0")
        data_per_month_1 = check_connection(request, cursor)
        debug(data_per_month_1 = data_per_month_1, debug = True)
        return JsonResponse({'data_per_month_1':data_per_month_1, 'prev_month': prev_month, 'this_year': this_year})

def rank_bfmonth_html(request):
    data_per_month_1 = {}
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    prev_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 1)
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))
    with connection.cursor() as cursor:
        cursor.execute("EXEC TMSP_VIS_Rangking_Dashboard @type = 0")
        data_per_month_1 = check_connection(request, cursor)
        debug(data_per_month_1 = data_per_month_1, debug = True)
    return render(request, 'rb_month.html', context={'data_per_month_1':data_per_month_1, 'prev_month': prev_month, 'this_year': this_year})

def rank_thismonth(request):
    data_per_month_2 = {}
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    this_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')))
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))
    with connection.cursor() as cursor:
        cursor.execute("EXEC TMSP_VIS_Rangking_Dashboard @type = 1")
        data_per_month_2 = check_connection(request, cursor)
        debug(data_per_month_2 = data_per_month_2, debug = True)
        return JsonResponse({'data_per_month_2':data_per_month_2, 'this_month': this_month, 'this_year': this_year})

def rank_thismonth_html(request):
    data_per_month_2 = {}
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    this_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')))
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))
    with connection.cursor() as cursor:
        cursor.execute("EXEC TMSP_VIS_Rangking_Dashboard @type = 1")
        data_per_month_2 = check_connection(request, cursor)
        debug(data_per_month_2 = data_per_month_2, debug = True)
    return render(request, 'rt_month.html', context={'data_per_month_2':data_per_month_2, 'this_month': this_month, 'this_year': this_year})

def rank_ytmonth(request=None, vendor=None, message=''):
    data_year_to_month = {}
    total_rank_1_1 = 0
    total_rank_1_2 = 0
    total_kenaikan_1 = 0
    total_presentase_1 = 0
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    prev_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 1)
    prev_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y')) - 1
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))

    vendor = request.GET.get('u') or vendor
    is_get = False
    if vendor:
        is_get = True
    template = 'data_not_found.html'

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        add_log(request, "rank_per_month", str(cc))
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            add_log(request, "rank_per_month", "Session telah berakhir")
            return getattr(views, cc[0])(request, cc[1])
        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')

    if vendor:
        template = 'index2.html'
        with connection.cursor() as cursor:
            cursor.execute("TMSP_VIS_YTM_DASHBOARD @Vendor = '{}'".format(vendor))
            data_year_to_month = check_connection(request, cursor)
            debug(data_year_to_month = data_year_to_month, debug = True)
            for i in data_year_to_month:
                total_rank_1_1 += i[2]
                total_rank_1_2 += i[3]
            total_kenaikan_1 = total_rank_1_2 - total_rank_1_1
            total_presentase_1 = (total_kenaikan_1 / total_rank_1_1) * 100
        if is_get:
            data = {'data_year_to_month':data_year_to_month, 'prev_month': prev_month, 'prev_year': prev_year,
            'this_year': this_year, 'total_rank_1_1':total_rank_1_1, 'total_rank_1_2':total_rank_1_2, 'total_kenaikan_1':total_kenaikan_1,
            'total_presentase_1':total_presentase_1}
        return JsonResponse({'data_year_to_month':data_year_to_month, 'prev_month': prev_month, 'prev_year': prev_year,
        'this_year': this_year, 'total_rank_1_1':total_rank_1_1, 'total_rank_1_2':total_rank_1_2, 'total_kenaikan_1':total_kenaikan_1,
        'total_presentase_1':total_presentase_1})

def rank_ytmonth_html(request=None, vendor=None, message=''):
    data = {}
    data_year_to_month = {}
    total_rank_1_1 = 0
    total_rank_1_2 = 0
    total_kenaikan_1 = 0
    total_presentase_1 = 0
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    prev_month = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 1)
    prev_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y')) - 1
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))

    vendor = request.GET.get('u') or vendor
    is_get = False
    if vendor:
        is_get = True
    template = 'data_not_found.html'

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        add_log(request, "rank_per_month", str(cc))
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            add_log(request, "rank_per_month", "Session telah berakhir")
            return getattr(views, cc[0])(request, cc[1])
        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')

    if vendor:
        template = 'index2.html'
        with connection.cursor() as cursor:
            cursor.execute("TMSP_VIS_YTM_DASHBOARD @Vendor = '{}'".format(vendor))
            data_year_to_month = check_connection(request, cursor)
            debug(data_year_to_month = data_year_to_month, debug = True)
            for i in data_year_to_month:
                total_rank_1_1 += i[2]
                total_rank_1_2 += i[3]
            total_kenaikan_1 = total_rank_1_2 - total_rank_1_1
            try:
                total_presentase_1 = (total_kenaikan_1 / total_rank_1_1) * 100
            except:
                return render(request, template, {})
        return render(request, 'report_month.html', context={'data_year_to_month':data_year_to_month, 'prev_month': prev_month, 'prev_year': prev_year,
            'this_year': this_year, 'total_rank_1_1':total_rank_1_1, 'total_rank_1_2':total_rank_1_2, 'total_kenaikan_1':total_kenaikan_1,
            'total_presentase_1':total_presentase_1})

def rank_ytdate(request=None, vendor=None, message=''):
    data_year_to_date = {}
    total_rank_2_1 = 0
    total_rank_2_2 = 0
    total_kenaikan_2 = 0
    total_presentase_2 = 0
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    prev_month2 = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 2)
    prev_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y')) - 1
    this_date = datetime.datetime.strftime(datetime.datetime.now(), '%d-%m-%Y')
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))

    vendor = request.GET.get('u') or vendor
    is_get = False
    if vendor:
        is_get = True
    template = 'data_not_found.html'

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        add_log(request, "rank_per_month", str(cc))
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            add_log(request, "rank_per_month", "Session telah berakhir")
            return getattr(views, cc[0])(request, cc[1])
        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')

    if vendor:
        template = 'index2.html'
        with connection.cursor() as cursor:
            cursor.execute("TMSP_VIS_YTD_DASHBOARD @Vendor = '{}'".format(vendor))
            data_year_to_date = check_connection(request, cursor)
            debug(data_year_to_date = data_year_to_date, debug = True)
            for i in data_year_to_date:
                total_rank_2_1 += i[2]
                total_rank_2_2 += i[3]
            total_kenaikan_2 = total_rank_2_2 - total_rank_2_1
            total_presentase_2 = (total_kenaikan_2 / total_rank_2_1) * 100
        if is_get:
            data = {'data_year_to_date':data_year_to_date, 'prev_month2':prev_month2, 'prev_year':prev_year,
            'this_date':this_date, 'this_year':this_year, 'total_rank_2_1':total_rank_2_1, 'total_rank_2_2':total_rank_2_2,
            'total_presentase_2':total_presentase_2}
        return JsonResponse({'data_year_to_date':data_year_to_date, 'prev_month2':prev_month2, 'prev_year':prev_year,
        'this_date':this_date, 'this_year':this_year, 'total_rank_2_1':total_rank_2_1, 'total_rank_2_2':total_rank_2_2,
        'total_presentase_2':total_presentase_2, 'total_kenaikan_2':total_kenaikan_2})

def rank_ytdate_html(request=None, vendor=None, message=''):
    data = {}
    data_year_to_date = {}
    total_rank_2_1 = 0
    total_rank_2_2 = 0
    total_kenaikan_2 = 0
    total_presentase_2 = 0
    data_month = {
        1: 'Januari',
        2: 'Februari',
        3: 'Maret',
        4: 'April',
        5: 'Mei',
        6: 'Juni',
        7: 'Juli',
        8: 'Agustus',
        9: 'September',
        10: 'Oktober',
        11: 'November',
        12: 'Desember',
    }
    prev_month2 = data_month.get(int(datetime.datetime.strftime(datetime.datetime.now(), '%m')) - 2)
    prev_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y')) - 1
    this_date = datetime.datetime.strftime(datetime.datetime.now(), '%d-%m-%Y')
    this_year = int(datetime.datetime.strftime(datetime.datetime.now(), '%Y'))

    vendor = request.GET.get('u') or vendor
    is_get = False
    if vendor:
        is_get = True
    template = 'data_not_found.html'

    if request:
        request.session.update({'prev': request.get_full_path()})
        cc = check_login(request)
        add_log(request, "rank_per_month", str(cc))
        debug(cc = cc, debug = True)
        if cc[0] and not isinstance(cc[0], bool):
            add_log(request, "rank_per_month", "Session telah berakhir")
            return getattr(views, cc[0])(request, cc[1])
        if not vendor:
            vendor = request.session.get('vendor_code') or request.session.get('username')

    if vendor:
        template = 'index2.html'
        with connection.cursor() as cursor:
            cursor.execute("TMSP_VIS_YTD_DASHBOARD @Vendor = '{}'".format(vendor))
            data_year_to_date = check_connection(request, cursor)
            debug(data_year_to_date = data_year_to_date, debug = True)
            for i in data_year_to_date:
                total_rank_2_1 += i[2]
                total_rank_2_2 += i[3]
            total_kenaikan_2 = total_rank_2_2 - total_rank_2_1
            debug(total_kenaikan_2 = total_kenaikan_2, debug = True)
            try:
                total_presentase_2 = (total_kenaikan_2 / total_rank_2_1) * 100
            except:
                return render(request, template, {})
            debug(total_presentase_2 = total_presentase_2, debug = True)
        return render(request, 'report_date.html', context={'data_year_to_date':data_year_to_date, 'prev_month2':prev_month2, 'prev_year':prev_year,
            'this_date':this_date, 'this_year':this_year, 'total_rank_2_1':total_rank_2_1, 'total_rank_2_2':total_rank_2_2,
            'total_presentase_2':total_presentase_2, 'total_kenaikan_2':total_kenaikan_2})

def cardsummary_po(request, vendor = ''):
    vendor = vendor or request.session.get('vendor_code') or request.session.get('username')
    cc = check_login(request)
    debug(cc = cc, debug = True)

    if cc[0] and not isinstance(cc[0], bool):
        debug("return to login", debug = True)
        notify.send("VIS", f"return to login", "index", "warning")
        return getattr(views, cc[0])(request, cc[1])
    elif cc[0] and isinstance(cc[0], bool):
        debug("goto dashboard", debug = True)
        with connection.cursor() as cursor:
            sql_script = "EXEC TMSP_VIS_Information_dashboard_po @vendor = '{}'".format(vendor)
            data = check_connection(request, cursor, sql_script)
            debug(data = data, debug = True)
            if not data:
                return render(request, 'database_error.html', {})
            total_po = data[0][1] or 0
        return JsonResponse({'total_po':total_po})

def cardsummary_grpo(request, vendor = ''):
    vendor = vendor or request.session.get('vendor_code') or request.session.get('username')
    cc = check_login(request)
    debug(cc = cc, debug = True)

    if cc[0] and not isinstance(cc[0], bool):
        debug("return to login", debug = True)
        notify.send("VIS", f"return to login", "index", "warning")
        return getattr(views, cc[0])(request, cc[1])
    elif cc[0] and isinstance(cc[0], bool):
        debug("goto dashboard", debug = True)
        with connection.cursor() as cursor:
            sql_script = "EXEC TMSP_VIS_Information_dashboard_grpo @vendor = '{}'".format(vendor)
            data = check_connection(request, cursor, sql_script)
            debug(data = data, debug = True)
            if not data:
                return render(request, 'database_error.html', {})
            total_grpo = data[0][1] or 0
        return JsonResponse({'total_grpo':total_grpo})

def cardsummary_gr(request, vendor = ''):
    vendor = vendor or request.session.get('vendor_code') or request.session.get('username')
    cc = check_login(request)
    debug(cc = cc, debug = True)

    if cc[0] and not isinstance(cc[0], bool):
        debug("return to login", debug = True)
        notify.send("VIS", f"return to login", "index", "warning")
        return getattr(views, cc[0])(request, cc[1])
    elif cc[0] and isinstance(cc[0], bool):
        debug("goto dashboard", debug = True)
        with connection.cursor() as cursor:
            sql_script = "EXEC TMSP_VIS_information_dashboard_gr @vendor = '{}'".format(vendor)
            data = check_connection(request, cursor, sql_script)
            debug(data = data, debug = True)
            if not data:
                return render(request, 'database_error.html', {})
            total_gr = data[0][1] or 0
        return JsonResponse({'total_gr':total_gr})

def cardsummary_ap_inv(request, vendor = ''):
    vendor = vendor or request.session.get('vendor_code') or request.session.get('username')
    cc = check_login(request)
    debug(cc = cc, debug = True)

    if cc[0] and not isinstance(cc[0], bool):
        debug("return to login", debug = True)
        notify.send("VIS", f"return to login", "index", "warning")
        return getattr(views, cc[0])(request, cc[1])
    elif cc[0] and isinstance(cc[0], bool):
        debug("goto dashboard", debug = True)
        with connection.cursor() as cursor:
            sql_script = "EXEC TMSP_VIS_information_dashboard_apinv @vendor = '{}'".format(vendor)
            data = check_connection(request, cursor, sql_script)
            debug(data = data, debug = True)
            if not data:
                return render(request, 'database_error.html', {})
            total_ap_inv = data[0][1] or 0
        return JsonResponse({'total_ap_inv':total_ap_inv})

def cardsummary_ap_mem(request, vendor = ''):
    vendor = vendor or request.session.get('vendor_code') or request.session.get('username')
    cc = check_login(request)
    debug(cc = cc, debug = True)

    if cc[0] and not isinstance(cc[0], bool):
        debug("return to login", debug = True)
        notify.send("VIS", f"return to login", "index", "warning")
        return getattr(views, cc[0])(request, cc[1])
    elif cc[0] and isinstance(cc[0], bool):
        debug("goto dashboard", debug = True)
        with connection.cursor() as cursor:
            sql_script = "EXEC TMSP_VIS_information_dashboard_apcm @vendor = '{}'".format(vendor)
            data = check_connection(request, cursor, sql_script)
            debug(data = data, debug = True)
            if not data:
                return render(request, 'database_error.html', {})
            total_ap_mem = data[0][1] or 0
        return JsonResponse({'total_ap_mem':total_ap_mem})

def cardsummary_grr(request, vendor = ''):
    vendor = vendor or request.session.get('vendor_code') or request.session.get('username')
    cc = check_login(request)
    debug(cc = cc, debug = True)

    if cc[0] and not isinstance(cc[0], bool):
        debug("return to login", debug = True)
        notify.send("VIS", f"return to login", "index", "warning")
        return getattr(views, cc[0])(request, cc[1])
    elif cc[0] and isinstance(cc[0], bool):
        debug("goto dashboard", debug = True)
        with connection.cursor() as cursor:
            sql_script = "EXEC TMSP_VIS_information_dashboard_grr @vendor = '{}'".format(vendor)
            data = check_connection(request, cursor, sql_script)
            debug(data = data, debug = True)
            if not data:
                return render(request, 'database_error.html', {})
            total_grr = data[0][1] or 0
        return JsonResponse({'total_grr':total_grr})

def test_h(request, ckroot=None):
    request.session.update({'prev': request.get_full_path()})
    vendor = request.session.get('vendor_code') or request.session.get('username')
    ckroot = check_is_root(request)
    debug(ckroot=ckroot, debug = True)
    if ckroot is True:
        return show_all_pass(request)
    return render(request, 'test_h.html',{'vendor':vendor, 'request':request})

def adduser(request):
    cc = check_login(request)
    debug(cc = cc, debug = True)
    if request.POST:
        username = request.POST.get('username')
        pass1 = request.POST.get('user_password')
        pass2 = request.POST.get('confirm_password')
        namavendor = request.POST.get('namavendor')
        status = request.POST.get('status')
        priv = request.POST.get('priv')
        cr = VIS_UserLogin.objects.create(UserNameLogin=username, PasswordLogin=crypt.encrypt(pass2, settings.ENCRYPT_KEY),
            NamaVendor=namavendor, KodeVendor=username, Status=status, Priv=priv, HasChangePassword="1")
        message = "User Berhasil Ditambahkan"
        response = {'message':message}
        return redirect('/add_user', {'message': message,})
        '''
        dtuser = None
        try:
            dtuser = VIS_UserLogin.objects.get(username=username)
            if username == dtuser.username:
                message = "Username sudah ada"
                response = {'message':message}
                return JsonResponse(response)
            else:
                cr = VIS_UserLogin.objects.create(UserNameLogin=username, PasswordLogin=crypt.encrypt(pass2, settings.ENCRYPT_KEY),
                    NamaVendor=namavendor, KodeVendor=username, Status=status, Priv=priv, HasChangePassword="1")
                message = "User Berhasil Ditambahkan"
                response = {'message':message}
                return JsonResponse(response)
        except:
            pass
        '''
    else:
        return render(request, 'add_user.html', {})


def edituser(request, object_id):
    usr = get_object_or_404(VIS_UserLogin, id=object_id)
    if request.method == "POST" :
        form = EditUserForm(request.POST, instance=kr)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.INFO, "Update User Berhasil")
            return redirect('/pass')
    else:
        form = EditUserForm(instance=usr)
    return render(request, 'edit_user.html',{'usr':usr, 'form':form})

def get_type_user(request, utype = 'operator'):
    USERS_OPERATOR = settings.USERS_OPERATOR or []
    return JsonResponse({'USERS_OPERATOR': USERS_OPERATOR,})
