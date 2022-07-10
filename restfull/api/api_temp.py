# Import random module
import random
import sys
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

def generator():
    # Set the character list for generating the api
    characters = "01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ&*(){}[]|/\?[email protected]#$%^abcdefghijklmnopqrstuvwxyz"
    # Take the length of the api from the user
    api_length = 32
    # Generate the api
    api = "".join(random.sample(characters, api_length))
    # Print the generated api
    api = md5.new(api).hexdigest()
    return api

if __name__ == '__main__':
    api = generator()
    print("Gernerated api: %s" %api)
    print("Gernerated MD5 api: %s" %api)