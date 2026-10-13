"""Examples for the current 3.9.5.81 named API, retaining legacy function names.

Unsupported legacy operations raise NotImplementedError before making a request.
These examples do not add Weixin 4.x support.
"""

import requests
import json


def check_login():
    """
     0.检查是否登录
    :return:
    """
    url = "http://127.0.0.1:19088/api/checkLogin"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def user_info():
    """
    登录用户信息
    :return:
    """
    url = "http://127.0.0.1:19088/api/userInfo"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def send_text():
    """
    发送文本
    :return:
    """
    url = "http://127.0.0.1:19088/api/sendTextMsg"
    payload = json.dumps({
        "wxid": "filehelper",
        "msg": "123"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def send_at():
    """
    发送@消息
    :return:
    """
    url = "http://127.0.0.1:19088/api/sendAtText"
    payload = json.dumps({
        "chatRoomId": "12333@chatroom",
        "wxids": "notify@all",
        "msg": "12333"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def send_img():
    """
    发送图片
    :return:
    """
    url = "http://127.0.0.1:19088/api/sendImagesMsg"
    payload = json.dumps({
        "wxid": "filehelper",
        "imagePath": "C:/123.png"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def send_file():
    """
    发送文件
    :return:
    """
    url = "http://127.0.0.1:19088/api/sendFileMsg"
    payload = json.dumps({
        "wxid": "filehelper",
        "filePath": "C:/test.txt"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def hook_msg():
    """
    hook 消息
    :return:
    """
    url = "http://127.0.0.1:19088/api/hookSyncMsg"
    payload = json.dumps({
        "port": "19099",
        "ip": "127.0.0.1",
        "enableHttp": 0
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def unhook_msg():
    """
    取消消息hook
    :return:
    """
    url = "http://127.0.0.1:19088/api/unhookSyncMsg"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def hook_img():
    """hook 图片
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "hook_img is not implemented by the current named API"
    )


def unhook_img():
    """取消hook 图片
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "unhook_img is not implemented by the current named API"
    )


def hook_voice():
    """hook 语音
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "hook_voice is not implemented by the current named API"
    )


def unhook_voice():
    """取消hook 语音
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "unhook_voice is not implemented by the current named API"
    )


def del_friend():
    """删除好友
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "del_friend is not implemented by the current named API"
    )


def search_friend():
    """网络搜素用户
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "search_friend is not implemented by the current named API"
    )


def add_friend():
    """添加好友
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "add_friend is not implemented by the current named API"
    )


def fetch_chat_room_members():
    """
    群成员
    :return:
    """
    url = "http://127.0.0.1:19088/api/getMemberFromChatRoom"
    payload = json.dumps({
        "chatRoomId": "2112222004@chatroom"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def get_member_nickname():
    """群成员昵称
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "get_member_nickname is not implemented by the current named API"
    )


def del_member():
    """
    删除群成员
    :return:
    """
    url = "http://127.0.0.1:19088/api/delMemberFromChatRoom"
    payload = json.dumps({
        "chatRoomId": "31122263384@chatroom",
        "memberIds": "wxid_12223334422"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def add_member():
    """
    增加群成员
    :return:
    """
    url = "http://127.0.0.1:19088/api/addMemberToChatRoom"
    payload = json.dumps({
        "chatRoomId": "1111163384@chatroom",
        "memberIds": "wxid_o12222222"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def modify_room_name():
    """
    修改群昵称
    :return:
    """
    url = "http://127.0.0.1:19088/api/modifyNickname"
    payload = json.dumps({
        "chatRoomId": "222285428@chatroom",
        "wxid": "wxid_222222512",
        "nickName": "qqq"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def get_db_handlers():
    """
    获取sqlite3的操作句柄
    :return:
    """
    url = "http://127.0.0.1:19088/api/getDBInfo"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def query_db_by_sql():
    """
    查询数据库
    :return:
    """
    url = "http://127.0.0.1:19088/api/execSql"
    payload = json.dumps({
        "dbHandle": 116201928,
        "sql": "select localId from MSG where MsgSvrID= 7533111101686156"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def hook_log():
    """
    hook 日志
    :return:
    """
    url = "http://127.0.0.1:19088/api/hookLog"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def unhook_log():
    """
    取消hook日志
    :return:
    """
    url = "http://127.0.0.1:19088/api/unhookLog"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def forward():
    """
    转发消息
    :return:
    """
    url = "http://127.0.0.1:19088/api/forwardMsg"
    payload = json.dumps({
        "wxid": "filehelper",
        "msgId": "705117679011122708"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def logout():
    """退出登录
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "logout is not implemented by the current named API"
    )


def confirm_receipt():
    """确认收款
    :return:

    当前 3.9.5.81 源码未实现此接口。
    """
    raise NotImplementedError(
        "confirm_receipt is not implemented by the current named API"
    )


def contact_list():
    """
    好友列表
    :return:
    """
    url = "http://127.0.0.1:19088/api/getContactList"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def room_detail():
    """
    群详情
    :return:
    """
    url = "http://127.0.0.1:19088/api/getChatRoomDetailInfo"
    payload = json.dumps({
        "chatRoomId": "199134446111@chatroom"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def ocr():
    """
    ocr提取文字
    :return:
    """
    url = "http://127.0.0.1:19088/api/ocr"
    payload = json.dumps({
        "imagePath": "C:\\WeChat Files\\b23e84997144dd12f21554b0.dat"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def pat():
    """
    拍一拍
    :return:
    """
    url = "http://127.0.0.1:19088/api/sendPatMsg"
    payload = json.dumps({
        "receiver": "211111121004@chatroom",
        "wxid": "wxid_111111111422"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def top_msg():
    """
    消息置顶
    :return:
    """
    url = "http://127.0.0.1:19088/api/topMsg"
    payload = json.dumps({
        "wxid": "wxid_o11114422",
        "msgId": 3728307145189195000
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def close_top_msg():
    """
    取消置顶
    :return:
    """
    url = "http://127.0.0.1:19088/api/removeTopMsg"
    payload = json.dumps({
        "chatRoomId": "213222231004@chatroom",
        "msgId": 3728307145189195000
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def sns_first():
    """
    朋友圈首页
    :return:
    """
    url = "http://127.0.0.1:19088/api/getSNSFirstPage"
    payload = {}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def sns_next():
    """
    朋友圈下一页
    :return:
    """
    url = "http://127.0.0.1:19088/api/getSNSNextPage"
    payload = json.dumps({
        "snsId": "14091988153735844377"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def query_nickname():
    """
    查询联系人资料，名称位于返回结果 data.nickname
    :return:
    """
    url = "http://127.0.0.1:19088/api/getContactProfile"

    payload = json.dumps({
        "wxid": "wxid_1112p4422"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def download_msg_attach():
    """
    下载消息附件
    :return:
    """
    url = "http://127.0.0.1:19088/api/downloadAttach"
    payload = json.dumps({
        "msgId": 6080100336053626000
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


def get_member_info():
    """
    获取群/群成员信息
    :return:
    """
    url = "http://127.0.0.1:19088/api/getContactProfile"
    payload = json.dumps({
        "wxid": "wxid_tx8k6tu21112"
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)


if __name__ == '__main__':
    check_login()
