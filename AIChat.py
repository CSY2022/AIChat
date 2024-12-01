from openai import OpenAI
import requests, json
from partial_json_parser import loads
from Crypto import Random
from Crypto.Cipher import AES
import base64
from hashlib import md5, sha256
from rich.markdown import Markdown
from rich.console import Console
from rich import print as rprint
import secrets
import string

#加密与解密

def generate_secure_random_string(length):
    letters = string.ascii_letters + string.digits
    secure_str = ''.join(secrets.choice(letters) for _ in range(length))
    return secure_str

def pad(data):
    text = (data + chr(16 - len(data) % 16) * (16 - len(data) % 16)).encode('utf-8')
    return text

def unpad(padded_data):
   padding_len = ord(padded_data[-1])
   if padding_len > len(padded_data) or padding_len == 0 or not all(c == padded_data[-1] for c in padded_data[-padding_len:]):
       return None  # Invalid padding
   return padded_data[:-padding_len]
 
def encrypt(message, passphrase):
    key_iv = key_to_bytes(passphrase, 48)
    key = key_iv[16:48]
    iv = key_iv[:16]
    print(len(key),len(iv))
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(aes.encrypt(pad(message)))
 
def decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    key_iv = key_to_bytes(passphrase, 48)
    key = key_iv[16:48]
    iv = key_iv[0:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted).decode(encoding='utf-8'))

def key_to_bytes(data, output):
    data=data.encode(encoding='utf-8')
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]

#OpenAI

def opai(key,url,model,messages):
    client = OpenAI(
        api_key = key,
        base_url = url + '/v1'
    )
    response = client.chat.completions.create(
        model = model,
        temperature = 0,
        stream = True,
        max_tokens = 1000,
        messages = messages   
    )
    print(f'ChatGPT:\n')
    answers=''
    print(f'流式输出：\n')
    for chunk in response:
        print(chunk.choices[0].delta.content or "", end="")
        answers += chunk.choices[0].delta.content or ''
    danswers = {"role": "assistant"}
    danswers["content"] = answers
    messages.append(danswers)
    print(f'\n')
    #print('\033c', end='')
    answer(answers)
    return messages

#Gemini

def geai(key,url,model,messages):
    data = {"contents":[{}]}
    GEMINI_API_URL = f'{url}/v1beta/models/{model}:streamGenerateContent?key={key}'
    headers = {'Content-Type': 'application/json'}
    data["contents"][0] = messages
    response = requests.post(url=GEMINI_API_URL, headers=headers, stream=True, data=json.dumps(data))
    answers = b''
    sanswers = ''
    print(f'Gemini:\n')
    print(f'流式输出：\n')
    for chunk in response:
        answers += chunk
        try:
            canswers = loads(answers.decode(encoding='utf-8'))
            lanswers = ''
            for i in range(0,len(canswers)):
                lanswers += canswers[i]['candidates'][0]['content']['parts'][0]['text']
                print(lanswers[len(sanswers):] or '', end = '')
                sanswers += lanswers[len(sanswers):]
        except:
            pass
    print(f'\n')
    #print('\033c', end='')
    answer(sanswers)
    danswers = {"role": "model","parts":[{"text":""}]}
    danswers["parts"][0]["text"] = sanswers
    messages.append(danswers)
    return messages

#对话

def ask(messages, assistant):
    question = input("用户: ")
    messages =messages
    print()
    if assistant == 'ChatGPT':
        dquestions = {"role": "user"}
        dquestions["content"] = question
        messages.append(dquestions)
        return messages
    if assistant == 'Gemini':
        dquestions = {"role": "user","parts":[{"text":""}]}
        dquestions["parts"][0]["text"] = question
        messages.append(dquestions)
        return messages

def answer(answers):
    '''
    markdown = Markdown(answers)
    console = Console()
    with console.capture() as capture:
        console.print(markdown)
    plain_text = capture.get()  
    print(plain_text)  
    '''
    rprint(Markdown(" **Markdown** 渲染输出："))
    print('')
    rprint(Markdown(answers))
    print('')

#登录

def login():
    print("本软件必须在遵循 OpenAI 的使用条款、Google 服务条款、Gemini API 附加服务条款以及软件使用者所在地区和国家的法律法规的情况下\
使用，不得用于非法用途。软件开发者不对使用者违规使用造成的不良影响及后果承担任何责任。根据《中华人民共和国生成式人工智能服务管理暂行办法》\
的要求，本软件不对中国地区公众提供一切未经备案的生成式人工智能服务。本软件仅用于非商业性的学习、研究、科研测试等合法用途，不得用于任何违法\
违规用途，否则自行承担相关责任。")
    print(f'\n')
    messages = []
    unverified = True
    while unverified:
        hashkey = sha256()
        hashkey.update(input("请输入密码:").encode(encoding='utf-8'))
        key = hashkey.hexdigest()
        try:
            encrypt_data = 'AwQmskAHVRGluKsyw3aXM95JAuYiWJkA2Bk/R+Lyw/fQ1I1Tw0MR0nfgMWvKeUlqh8lrQY+yLzhgrf9ZhzqSuQ=='
            encrypt_data2 = '73nD9vnGDeQS1fQ89vkFA7qJtmIrAmcjsQ0c1xNvuvoIHj6X9xebaJebB1+SZUgv'
            modify_json('./config/configure.json',['AIChat','Gemini'],encrypt_data)
            modify_json('./config/configure.json',['AIChat','ChatGPT'],encrypt_data2)
            decrypt_data = decrypt(encrypt_data, key)
            decrypt_data2 = decrypt(encrypt_data2, key)
            print(decrypt_data,decrypt_data2)
            unverified= False
        except:
            print(f'\n密码错误,请重新输入！\n')

    print(f'\n验证通过\n')
    while True:
        assistant = 'Gemini'
        messages = ask(messages, assistant)
        if assistant == 'ChatGPT':
            messages = opai(decrypt_data,'https://api.gpt.ge','gpt-4o',messages)
        elif assistant == 'Gemini':
            messages = geai(decrypt_data2,'https://palm.csy2022.top','gemini-pro',messages)

#注册

def register():
    print('愿 与子偕行')
    #while password == '':
    #   print('为确保一定程度上的安全性，软件会对本地存储的密钥加密，请设置一个密码来帮助我们做到这点。')
    #   password = input('请设置密码：')
    #   if password == input('请再次确认您的密码：'):
    #       print('请妥善保管密码，如果您忘记了您的密码，唯一的恢复手段是清空数据!')
    #   else:
    #       password = ''
    password = generate_secure_random_string(64)
    return password

# 写入 JSON 文件的函数
def write_json(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, ensure_ascii=False, indent=4)
    print(f"数据已写入 {file_path} 文件")

# 读取 JSON 文件的函数
def read_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
    return data

# 修改多层嵌套值的函数
def modify_json(file_path, keys, new_value):
    # 读取现有数据
    data = read_json(file_path)
    
    # 遍历键路径，直到找到目标值
    temp_data = data
    for key in keys[:-1]:  # 遍历到倒数第二个键
        if isinstance(temp_data, dict) and key in temp_data:
            temp_data = temp_data[key]
        else:
            print(f"键 '{key}' 不存在于 JSON 数据中或类型不匹配")
            return
    
    # 修改最后一个键的值
    last_key = keys[-1]
    if isinstance(temp_data, dict) and last_key in temp_data:
        temp_data[last_key] = new_value
        print(f"已将 '{'.'.join(keys)}' 的值修改为 '{new_value}'")
    else:
        print(f"键 '{last_key}' 不存在于 JSON 数据中或类型不匹配")
        return
    
    # 将修改后的数据写回文件
    write_json(file_path, data)


if __name__ == '__main__':
    login()
