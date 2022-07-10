Restfull Example for Whalez Test
====================================

Author
===============
Hadi Cahyadi

Requirements
=================
    - python 3+
    - Django 3.1.4+
    - mysqlclient
    - pydebugger
    - pytz


Install
============
```python
    >>> pip install 'django>=3.1.4'
    >>> pip install pydebugger
    >>> pip install pytz
    >>> pip install mysqlclient
    >>>
```

How to use
=============

```bash
    $ get clone https://github.com/cumulus13/restfull
    $ cd restfull/restfull
    $ python manager.py migrate
    $ python manager.py runserver 0.0.0.0:83
```

prepare database
-----------------

```bash
    $ cd restfull/restfull
    $ sudo su
    # mysql -u root
```
```mysql
    mysql> grant all privileges on restfull.* to 'restfull'@'127.0.0.1' identified by 'mypassword';
    mysql> create database restfull;
    mysql> use restfull;
    mysql> source mysql.sql;
```

    open http://127.0.0.1:83 with you favorite browser

```bash
    $ chrome http://127.0.0.1:83
```

Description
===============
    all link paths is:

    - 'api' => get user info with input[POST/GET] api or generate new temp api
    - 'api/login' => user login  (input[POST/GET]: username, password)
    - 'api/logout' => logout
    - 'api/singup' => add user/singup  (input[POST/GET]: username, password, email)
    - 'api/forgot' => forgot password
    - 'api/product' => get/show all or by name
    - 'api/product/add' => add product (input[POST/GET]: name, category_id, user_id)
    - 'api/product/get' => get/show all or by name
    - 'api/product/delete' => delete one product
    - 'api/product/del' => delete one product
    - 'api/product/edit' => edit/update one product
    - 'api/product/update' => edit/update one product
    - 'api/cart' => show all cart  (input[POST/GET]: name, name, user_id)
    - 'api/cart/add' => add item to cart
    - 'api/cart/get' => get all/one item cart
    - 'api/cart/delete' => delete one item cart
    - 'api/cart/del' =>  delete one item cart
    - 'api/category' => show all/one category
    - 'api/category/add' => add one category  (input[POST/GET]: name, category_id)
    - 'api/category/get' => get all/one category
    - 'api/category/delete' => delete one category
    - 'api/category/del' => delete one category
    - 'api/category/edit' => edit/update one category
    - 'api/category/update' => edit/update one category
    - 'api/cat' => show all/one category
    - 'api/cat/add' => add one category  (input[POST/GET]: name, category_id)
    - 'api/cat/get' => get all/one category
    - 'api/cat/delete' => delete one category
    - 'api/cat/del' => delete one category
    - 'api/cat/edit' => edit/update one category
    - 'api/cat/update' => edit/update one category

    * data input can given by GET or POST

    this use a temp api key before you create it by singup, you can get a temp api key at mysql table 'temp_api' by mysql command'

Example
==========
login
--------

```html
    http://127.0.0.1:83/api/login?api=9cfda27965750289691a283a203395ff&username=hadi&password=mypassword
```

output:
```json
        {"data": {"username": "hadi", "password": "mypassword", "status": "active", "islogin": "1", "id": "1", "api_key": "ce8c9ffe070ff1576067d66bea3b1fed", "email": "cumulus13@gmail.com"}, "message": "please login before !"}
```
    `9cfda27965750289691a283a203395ff` is a temp api key from `temp_api` table
    for the next login you have to use the new api key which is `ce8c9ffe070ff1576067d66bea3b1fed` which is the output of the example above. The api_key will also be stored in session, so if you log in only by inputting your username and password, the system will take it as granted if you not logged out

singup
--------

```html
    http://127.0.0.1:83/api/singup?api=9cfda27965750289691a283a203395ff&username=hadi&password=mypassword&email=cumulus13@gmail.com
```

output:
```json
        {"data": [[2, "2", "hadi", "hadi", "active", "0", "2", "28d01b008f5eab6977722cb8bcacc8d7", "cumulus13@gmail.com"]], "status": "success", "message": "please login with username and password"}
```
    `9cfda27965750289691a283a203395ff` is a temp api key from `temp_api` table
    for the next login you have to use a new api key which is `ce8c9ffe070ff1576067d66bea3b1fed` which is the output of the example above. for the singup process, the api_key will not be stored in the session, so you must first login to enter the system
