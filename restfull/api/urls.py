from django.urls import path, re_path
from django.views.generic.base import RedirectView
from . views import *
#from rest_framework.authtoken.views import obtain_auth_token
from django.views.generic import TemplateView

urlpatterns = [
    path('', login),
    path('/login', login),
    path('/logout', logout),
    path('/singup', singup),
    path('/forgot', forgot_password),
    path('/product', get_product),
    path('/product/add', add_product),
    path('/product/get', get_product),
    path('/product/delete', delete_product),
    path('/product/del', delete_product),
    path('/product/edit', update_product),
    path('/product/update', update_product),
    path('/cart', get_cart),
    path('/cart/add', add_cart),
    path('/cart/get', get_cart),
    path('/cart/delete', delete_cart),
    path('/cart/del', delete_cart),
    path('/category', get_category),
    path('/category/add', add_category),
    path('/category/get', get_category),
    path('/category/delete', delete_category),
    path('/category/del', delete_category),
    path('/category/edit', update_category),
    path('/category/update', update_category),
    path('/cat', get_category),
    path('/cat/add', add_category),
    path('/cat/get', get_category),
    path('/cat/delete', delete_category),
    path('/cat/del', delete_category),
    path('/cat/edit', update_category),
    path('/cat/update', update_category),
    path('/userinfo', get_user),
    path('/send_email', send_email),
]

#handler404='web.views.handle_page_not_found_404'