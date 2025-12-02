import requests
import json
from typing import Dict, List, Optional, Union, Any
from config import api_key
import time
import os
import re
import argparse
import csv
import sys
import traceback
import datetime

#https://twitterapi.io/dashboard 使用需要去充值

BASE_URL = "https://api.twitterapi.io"
# 创建一个存储目录
SAVE_DIR = "twitter_data"
if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

# 错误日志文件路径
ERROR_LOG_FILE = os.path.join(SAVE_DIR, "error.log")

def log_error(error_info: Dict):
    """
    将错误信息记录到统一的error.log文件中
    
    Args:
        error_info: 错误信息字典
    """
    try:
        # 获取当前时间，格式化为可读字符串
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 格式化错误信息
        error_message = f"[{current_time}] {error_info['error_type']}: {error_info['error_message']}\n"
        error_message += f"URL: {error_info.get('request_url', 'N/A')}\n"
        error_message += f"Params: {json.dumps(error_info.get('request_params', {}))}\n"
        if 'status_code' in error_info:
            error_message += f"Status Code: {error_info['status_code']}\n"
        if 'response_content' in error_info:
            error_message += f"Response: {error_info['response_content'][:200]}...\n" if len(error_info['response_content']) > 200 else f"Response: {error_info['response_content']}\n"
        error_message += f"Tweet ID: {error_info.get('tweet_id', 'N/A')}\n"
        error_message += "-" * 80 + "\n"
        
        # 追加写入错误日志文件
        with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(error_message)
        
        print(f"错误信息已记录到: {ERROR_LOG_FILE}")
    except Exception as e:
        print(f"记录错误信息失败: {e}")

def decode_unicode_text(obj):
    """
    递归解码Unicode编码的文本
    
    Args:
        obj: 任意Python对象（字典、列表、字符串等）
        
    Returns:
        解码后的对象
    """
    if isinstance(obj, str):
        return obj  # 字符串已经是解码状态，不需要额外处理
    elif isinstance(obj, dict):
        return {k: decode_unicode_text(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decode_unicode_text(item) for item in obj]
    else:
        return obj
    
def extract_crypto_addresses(text):
    """
    提取文本中的加密货币地址
    1. 先提取所有可能是地址的长字符串
    2. 根据长度和特征匹配最可能的链地址
    3. 遵循标记优先原则，如"BTC:"标记的地址优先识别为BTC
    """
    addresses = []
    address_set = set()  # 使用集合来避免重复地址
    
    # 保存原始文本供参考
    original_text = text
    
    # 首先提取以太坊格式地址(0x开头)，因为它们有明确的格式
    eth_addresses = re.findall(r'0x[a-fA-F0-9]{40}', text)
    for addr in eth_addresses:
        if addr not in address_set:
            address_set.add(addr)
            addresses.append({"type": "ETH", "address": addr})
    
    # 预处理文本 - 将换行符替换为空格，避免影响边界匹配
    text = text.replace('\n', ' ').replace('\r', ' ')
    
    # 识别文本中的连续长英文+数字文本
    # 使用更宽松的匹配方式，不要求边界，以便在各种环境中识别地址
    potential_addresses = re.findall(r'[A-Za-z0-9]{25,60}', text)
    
    # 检查每个潜在地址并识别类型
    for addr in potential_addresses:
        # 跳过已添加的地址
        if addr in address_set:
            continue
            
        # 检测地址类型
        addr_type = detect_address_type(addr)
        if addr_type:
            address_set.add(addr)
            addresses.append({"type": addr_type, "address": addr})
            print(f"识别为 {addr_type} 地址: {addr}")
    
    # 先查找带有明确标记的地址 (如 "BTC: address", "ETH: address" 等)
    coin_markers = {
        "BTC:": "BTC", 
        "ETH:": "ETH", 
        "SOL:": "SOL", 
        "TRON:": "TRON", 
        "TRX:": "TRON", 
        "XRP:": "XRP", 
        "ADA:": "ADA", 
        "LTC:": "LTC", 
        "DOGE:": "DOGE", 
        "DOT:": "DOT"
    }
    
    # 存储已识别地址的位置，防止重复匹配
    matched_ranges = []
    
    # 处理带明确标记的地址
    for marker, coin_type in coin_markers.items():
        marker_pos = text.find(marker)
        while marker_pos != -1:
            # 找到标记后的地址部分
            start = marker_pos + len(marker)
            # 找结束位置 (下一个空格或行尾)
            end = text.find(" ", start)
            if end == -1:  # 如果没有找到空格，则取到字符串结尾
                end = len(text)
            
            potential_address = text[start:end].strip()
            
            # 验证地址格式并且确保未重复添加
            if len(potential_address) >= 25 and is_valid_crypto_address(potential_address, coin_type) and potential_address not in address_set:
                address_set.add(potential_address)
                addresses.append({"type": coin_type, "address": potential_address})
                # 记录已匹配范围
                matched_ranges.append((start, end))
            
            # 继续查找下一个相同的标记
            marker_pos = text.find(marker, marker_pos + 1)
    
    # 返回最终结果前，确保没有重复地址
    unique_addresses = []
    seen = set()
    
    for addr_info in addresses:
        addr = addr_info["address"]
        if addr not in seen:
            seen.add(addr)
            unique_addresses.append(addr_info)
    
    if len(unique_addresses) != len(addresses):
        print(f"移除了 {len(addresses) - len(unique_addresses)} 个重复地址")
    
    return unique_addresses

def detect_address_type(addr):
    """
    检测加密货币地址的类型
    
    Args:
        addr: 地址字符串
        
    Returns:
        str: 地址类型，如果无法识别则返回None
    """
    # 检测顺序很重要！先检查有明确前缀的类型
    
    # 以太坊地址 (0x前缀)
    if addr.startswith("0x") and len(addr) == 42 and re.match(r'^0x[a-fA-F0-9]{40}$', addr):
        return "ETH"
    
    # 比特币地址 (1, 3, bc1前缀)
    if addr.startswith("1") and len(addr) >= 26 and len(addr) <= 34:
        return "BTC"
    if addr.startswith("3") and len(addr) >= 26 and len(addr) <= 34:
        return "BTC"
    if addr.startswith("bc1") and len(addr) >= 40 and len(addr) <= 60:
        return "BTC"
    
    # 波场地址 (T前缀)
    if addr.startswith("T") and len(addr) == 34:
        return "TRON"
    
    # 瑞波币地址 (r前缀)
    if addr.startswith("r") and len(addr) >= 25 and len(addr) <= 35:
        return "XRP"
    
    # 卡尔达诺地址 (addr1前缀)
    if addr.startswith("addr1") and len(addr) >= 10:
        return "ADA"
    
    # 莱特币地址 (L或M前缀)
    if (addr.startswith("L") or addr.startswith("M")) and len(addr) >= 27 and len(addr) <= 34:
        return "LTC"
    
    # 狗狗币地址 (D前缀)
    if addr.startswith("D") and len(addr) >= 33:
        return "DOGE"
    
    # 波卡地址 (1前缀，但要避免与比特币地址混淆)
    if addr.startswith("1") and len(addr) == 48:
        return "DOT"
    
    # Solana地址 (无明确前缀，最后检查)
    # 采用更宽松的检测规则，只检查长度和字母数字字符
    if len(addr) == 44 and re.match(r'^[A-Za-z0-9]{44}$', addr):
        return "SOL"
    
    # 其他未知的加密货币格式地址
    if len(addr) >= 30 and re.match(r'^[A-Za-z0-9]{30,}$', addr):
        return "UNKNOWN"
    
    return None

def is_valid_crypto_address(addr, expected_type=None):
    """
    验证加密货币地址格式是否合法
    
    Args:
        addr: 地址字符串
        expected_type: 预期的地址类型，如果提供则进行特定验证
        
    Returns:
        bool: 地址是否有效
    """
    # 如果预期类型是以太坊
    if expected_type == "ETH":
        # 以太坊地址验证
        return addr.startswith("0x") and len(addr) == 42 and re.match(r'^0x[a-fA-F0-9]{40}$', addr) is not None
    
    # 如果预期类型是比特币
    elif expected_type == "BTC":
        # 比特币地址验证 - 使用更宽松的规则
        if addr.startswith("1") or addr.startswith("3"):
            return len(addr) >= 26 and len(addr) <= 34 and re.match(r'^[A-Za-z0-9]{26,34}$', addr) is not None
        elif addr.startswith("bc1"):
            return len(addr) >= 40 and len(addr) <= 60 and re.match(r'^bc1[A-Za-z0-9]{39,59}$', addr) is not None
        return False
    
    # 如果预期类型是波场
    elif expected_type == "TRON":
        # 波场地址验证
        return addr.startswith("T") and len(addr) == 34 and re.match(r'^T[A-Za-z0-9]{33}$', addr) is not None
    
    # 如果预期类型是瑞波币
    elif expected_type == "XRP":
        # 瑞波币地址验证
        return addr.startswith("r") and len(addr) >= 25 and len(addr) <= 35 and re.match(r'^r[A-Za-z0-9]{24,35}$', addr) is not None
    
    # 如果预期类型是卡尔达诺
    elif expected_type == "ADA":
        # 卡尔达诺地址验证
        return addr.startswith("addr1") and len(addr) >= 10 and re.match(r'^addr1[A-Za-z0-9]{6,100}$', addr) is not None
    
    # 如果预期类型是波卡
    elif expected_type == "DOT":
        # 波卡地址验证
        return addr.startswith("1") and len(addr) == 48 and re.match(r'^1[A-Za-z0-9]{47}$', addr) is not None
    
    # 如果预期类型是莱特币
    elif expected_type == "LTC":
        # 莱特币地址验证
        return (addr.startswith("L") or addr.startswith("M")) and len(addr) >= 27 and len(addr) <= 34 and re.match(r'^[LM][A-Za-z0-9]{26,33}$', addr) is not None
    
    # 如果预期类型是狗狗币
    elif expected_type == "DOGE":
        # 狗狗币地址验证
        return addr.startswith("D") and len(addr) >= 33 and re.match(r'^D[A-Za-z0-9]{32,}$', addr) is not None
    
    # 如果预期类型是Solana
    elif expected_type == "SOL":
        # Solana地址验证 - 使用更宽松的规则
        return len(addr) == 44 and re.match(r'^[A-Za-z0-9]{44}$', addr) is not None
    
    # 如果预期类型是未知类型
    elif expected_type == "UNKNOWN":
        # 未知加密货币格式地址 - 使用通用验证
        return len(addr) >= 30 and re.match(r'^[A-Za-z0-9]{30,}$', addr) is not None
    
    # 如果没有预期类型，检测地址类型
    else:
        return detect_address_type(addr) is not None

def extract_tweet_id(url: str) -> Optional[str]:
    """
    从Twitter/X链接中提取tweet_id
    
    支持以下格式:
    - https://twitter.com/username/status/1234567890123456789
    - https://x.com/username/status/1234567890123456789
    - twitter.com/username/status/1234567890123456789
    - @username/status/1234567890123456789
    - 任何包含/status/id的格式
    
    Args:
        url: Twitter/X的链接或格式字符串
        
    Returns:
        提取的tweet_id或None（如果未找到）
    """
    # 支持多种格式的正则表达式
    patterns = [
        r'(?:https?:)?(?:\/\/)?(?:www\.)?(?:twitter|x)\.com\/(?:#!\/)?(?:[\w_]+)\/status(?:es)?\/(\d+)',
        r'(?:https?:)?(?:\/\/)?(?:www\.)?(?:[\w_]+)\/status(?:es)?\/(\d+)',
        r'\/status(?:es)?\/(\d+)',
        r'status\/(\d+)'
    ]
    
    # 处理可能出现的@符号
    if url.startswith('@'):
        url = 'https://twitter.com/' + url[1:]
    
    # 尝试不同的模式
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    # 如果所有模式都失败，尝试直接提取数字
    # 这是一个后备方法，查找链接中最长的数字序列（假设是ID）
    numbers = re.findall(r'\d+', url)
    if numbers:
        # 找出最长的数字序列(Twitter ID通常很长)
        longest_number = max(numbers, key=len)
        if len(longest_number) > 15:  # Twitter ID通常至少18位数字
            return longest_number
    
    return None

class TwitterApiIO:
    def __init__(self, api_key: str = api_key):
        self.api_key = api_key
        self.headers = {"X-API-Key": self.api_key}
        # 存储找到的地址（内存中而不是文件中）
        self.addresses_data = {}
    
    def validate_api(self) -> Dict[str, Any]:
        """
        验证API是否有效，通过尝试获取Elon Musk的用户信息
        
        Returns:
            包含验证结果的字典
        """
        try:
            print("正在验证API有效性...")
            result = self.get_user_info("elonmusk")
            if result.get("status") == "success" and "data" in result:
                user_info = result.get("data", {})
                print(f"API验证成功! 获取到用户: {user_info.get('name', 'N/A')} (@{user_info.get('userName', 'N/A')})")
                return {"is_valid": True, "message": "API验证成功", "user_info": user_info}
            else:
                error_msg = result.get("msg", "未知错误")
                print(f"API验证失败: {error_msg}")
                return {"is_valid": False, "message": f"API响应错误: {error_msg}", "response": result}
        except Exception as e:
            error_message = f"API验证出错: {str(e)}"
            print(error_message)
            return {"is_valid": False, "message": error_message}
    def get_user_info(self, username: str) -> Dict:
        """
        获取Twitter用户信息
        
        Args:
            username: 用户的屏幕名称
            
        Returns:
            用户信息的字典
        """
        url = f"{BASE_URL}/twitter/user/info"
        params = {"userName": username}
        
        response = requests.get(url, headers=self.headers, params=params)
        return response.json()
    
    def get_tweets_by_ids(self, tweet_ids: List[str]) -> Dict:
        """
        通过推文ID获取推文
        
        Args:
            tweet_ids: 推文ID列表
            
        Returns:
            包含推文信息的字典
        """
        url = f"{BASE_URL}/twitter/tweets"
        tweet_ids_str = ",".join(tweet_ids)
        params = {"tweet_ids": tweet_ids_str}
        
        response = requests.get(url, headers=self.headers, params=params)
        return response.json()
    
    def _filter_tweet_fields(self, tweet: Dict) -> Dict:
        """
        筛选推文字段，只保留指定的字段，并提取加密货币地址
        
        Args:
            tweet: 原始推文数据
            
        Returns:
            筛选后的推文数据
        """
        filtered_tweet = {
            "id": tweet.get("id", ""),
            "twitterUrl": tweet.get("twitterUrl", ""),
            "text": tweet.get("text", ""),
            "createdAt": tweet.get("createdAt", "")
        }
        
        # 只保留作者的指定字段
        if "author" in tweet:
            author = tweet["author"]
            filtered_tweet["author"] = {
                "id": author.get("id", ""),
                "userName": author.get("userName", ""),
                "name": author.get("name", ""),
                "profilePicture": author.get("profilePicture", ""),
                "createdAt": author.get("createdAt", "")
            }
            
            # 处理作者描述，有的在profile_bio中，有的在description中
            description = ""
            if "profile_bio" in author and "description" in author["profile_bio"]:
                description = author["profile_bio"].get("description", "")
            else:
                description = author.get("description", "")
                
            filtered_tweet["author"]["description"] = description
            
            # 提取文本和描述中的加密货币地址
            text_addresses = extract_crypto_addresses(filtered_tweet["text"])
            desc_addresses = extract_crypto_addresses(description)
            
            # 合并去重
            all_addresses = []
            address_set = set()
            
            for addr in text_addresses + desc_addresses:
                addr_key = f"{addr['type']}:{addr['address']}"
                if addr_key not in address_set:
                    address_set.add(addr_key)
                    all_addresses.append(addr)
            
            # 只有在找到地址时才添加addresses字段
            if all_addresses:
                filtered_tweet["addresses"] = all_addresses
                
                # 创建精简版本用于保存
                simplified_tweet = {
                    "author": {
                        "id": filtered_tweet["author"]["id"],
                        "userName": filtered_tweet["author"]["userName"],
                        "name": filtered_tweet["author"]["name"],
                        "description": filtered_tweet["author"]["description"]
                    },
                    "text": filtered_tweet["text"],
                    "twitterUrl": filtered_tweet["twitterUrl"],
                    "addresses": all_addresses
                }
                
                # 保存到内存中而不是文件
                self._add_address_info(simplified_tweet)
                
        return filtered_tweet
    
    def _add_address_info(self, tweet_with_addresses):
        """
        将包含加密货币地址的推文信息保存到内存
        使用纯地址字符串作为主键组织数据
        
        Args:
            tweet_with_addresses: 包含地址的推文信息
        """
        # 处理当前推文中的地址
        for addr in tweet_with_addresses.get("addresses", []):
            addr_key = addr['address']  # 直接使用地址作为键
            
            # 如果地址不存在，初始化
            if addr_key not in self.addresses_data:
                self.addresses_data[addr_key] = {
                    "type": addr["type"],
                    "mentions": []
                }
            
            # 创建提及记录
            mention = {
                "author": tweet_with_addresses.get("author", {}),
                "text": tweet_with_addresses.get("text", ""),
                "twitterUrl": tweet_with_addresses.get("twitterUrl", "")
            }
            
            # 检查是否已存在相同的提及（通过twitterUrl判断）
            mention_exists = False
            for existing_mention in self.addresses_data[addr_key]["mentions"]:
                if existing_mention.get("twitterUrl") == mention.get("twitterUrl"):
                    # 更新现有提及
                    existing_mention.update(mention)
                    mention_exists = True
                    break
            
            # 如果不存在，添加新提及
            if not mention_exists:
                self.addresses_data[addr_key]["mentions"].append(mention)
    
    def get_tweet_replies(self, tweet_id: str, since_time: Optional[int] = None, 
                         until_time: Optional[int] = None, cursor: str = "", 
                         decode_text: bool = True, filter_fields: bool = True) -> Dict:
        """
        获取推文的回复
        
        Args:
            tweet_id: 推文ID
            since_time: 开始时间（Unix时间戳，秒）
            until_time: 结束时间（Unix时间戳，秒）
            cursor: 分页游标，第一页为空字符串
            decode_text: 是否解码文本为可读格式
            filter_fields: 是否筛选只返回关键字段
            
        Returns:
            包含回复信息的字典
        """
        url = f"{BASE_URL}/twitter/tweet/replies"
        params = {"tweetId": tweet_id}
        
        if since_time:
            params["sinceTime"] = since_time
        if until_time:
            params["untilTime"] = until_time
        if cursor:
            params["cursor"] = cursor
            
        try:
            print(f"发送请求: {url} 参数: {params}")
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()  # 检查HTTP错误
            
            result = response.json()
            print(f"API响应状态: {result.get('status', 'unknown')}, 消息: {result.get('message', 'N/A')}")
            
            # 处理解码
            if decode_text and result.get("status") == "success" and "replies" in result:
                # 确保编码适合中文显示
                result = decode_unicode_text(result)
                
                # 为每条回复添加可读格式
                for reply in result.get("replies", []):
                    reply["readable"] = self._format_tweet_readable(reply)
            
            # 筛选字段，只保留指定字段
            if filter_fields and "tweets" in result:
                result["tweets"] = [self._filter_tweet_fields(tweet) for tweet in result["tweets"]]
            
            return result
            
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            # 创建错误信息字典
            error_info = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "timestamp": time.time(),
                "request_url": url,
                "request_params": params,
                "tweet_id": tweet_id
            }
            
            # 如果是HTTP错误，获取响应内容
            if isinstance(e, requests.exceptions.HTTPError):
                error_info["status_code"] = response.status_code
                try:
                    error_info["response_content"] = response.text
                except:
                    error_info["response_content"] = "无法获取响应内容"
            
            # 记录错误信息到统一的错误日志文件
            log_error(error_info)
            
            # 返回错误信息
            if isinstance(e, requests.exceptions.RequestException):
                print(f"请求错误: {e}")
                return {"status": "error", "message": str(e), "replies": []}
            elif isinstance(e, json.JSONDecodeError):
                print(f"JSON解析错误: {response.text}")
                return {"status": "error", "message": "无效的JSON响应", "replies": []}
            else:
                return {"status": "error", "message": str(e), "replies": []}
    
    def _format_tweet_readable(self, tweet_data):
        """
        将推文数据格式化为可读格式
        
        Args:
            tweet_data: 推文数据
            
        Returns:
            格式化后的推文信息字典
        """
        if not tweet_data:
            return {"error": "没有推文数据"}
        
        try:
            readable = {
                "id": tweet_data.get('id', 'N/A'),
                "内容": tweet_data.get('text', ''),
                "作者": {
                    "名称": tweet_data.get('author', {}).get('name', 'N/A'),
                    "用户名": tweet_data.get('author', {}).get('userName', 'N/A'),
                    "ID": tweet_data.get('author', {}).get('id', 'N/A'),
                    "简介": tweet_data.get('author', {}).get('description', ''),
                    "粉丝数": tweet_data.get('author', {}).get('followers', 0)
                },
                "发布时间": tweet_data.get('createdAt', 'N/A'),
                "统计数据": {
                    "点赞": tweet_data.get('likeCount', 0),
                    "回复": tweet_data.get('replyCount', 0),
                    "转发": tweet_data.get('retweetCount', 0),
                    "引用": tweet_data.get('quoteCount', 0)
                }
            }
            
            if 'viewCount' in tweet_data:
                readable["统计数据"]["浏览"] = tweet_data.get('viewCount', 0)
                
            # 添加实体信息(标签、链接等)
            if "entities" in tweet_data:
                readable["实体"] = {}
                entities = tweet_data["entities"]
                
                if "hashtags" in entities and entities["hashtags"]:
                    readable["实体"]["标签"] = [tag.get("text") for tag in entities["hashtags"]]
                    
                if "urls" in entities and entities["urls"]:
                    readable["实体"]["链接"] = [
                        {
                            "显示URL": url.get("display_url", ""),
                            "展开URL": url.get("expanded_url", "")
                        } for url in entities["urls"]
                    ]
                    
                if "user_mentions" in entities and entities["user_mentions"]:
                    readable["实体"]["提及用户"] = [
                        {
                            "名称": mention.get("name", ""),
                            "用户名": mention.get("screen_name", "")
                        } for mention in entities["user_mentions"]
                    ]
            
            return readable
        except Exception as e:
            return {"error": f"格式化推文时出错: {e}"}
    
    def get_all_tweet_replies(self, tweet_id: str, since_time: Optional[int] = None, 
                             until_time: Optional[int] = None, max_pages: int = 10,
                             filter_fields: bool = True) -> Dict[str, Any]:
        """
        获取推文的所有回复（自动处理分页）
        
        Args:
            tweet_id: 推文ID
            since_time: 开始时间（Unix时间戳，秒）
            until_time: 结束时间（Unix时间戳，秒）
            max_pages: 最大获取页数，防止无限循环
            filter_fields: 是否筛选只返回关键字段
            
        Returns:
            包含所有回复的字典
        """
        all_replies = []
        cursor = ""
        page_count = 0
        
        print(f"开始获取推文 {tweet_id} 的所有回复...")
        
        while page_count < max_pages:
            page_count += 1
            print(f"获取第 {page_count} 页, 使用游标: {cursor or '(空)'}")
            
            result = self.get_tweet_replies(tweet_id, since_time, until_time, cursor, filter_fields=filter_fields)
            
            # 检查API调用是否成功
            if result.get("status") != "success":
                print(f"API调用失败: {result.get('message', '未知错误')}")
                if page_count == 1:  # 如果第一页就失败，返回整个结果以便调试
                    return {
                        "replies": [],
                        "total_count": 0,
                        "pages_fetched": page_count,
                        "status": "error",
                        "error_details": result,
                        "raw_response": result
                    }
                break
                
            # 获取当前页的回复
            replies = result.get("tweets", [])
            print(f"当前页获取到 {len(replies)} 条回复")
            
            if not replies:
                print("没有获取到回复，可能是推文没有回复或者API限制")
                if page_count == 1:  # 如果第一页就没有回复，返回原始响应以便调试
                    return {
                        "replies": [],
                        "total_count": 0,
                        "pages_fetched": page_count,
                        "status": "success",
                        "raw_response": result
                    }
                break
                
            all_replies.extend(replies)
            
            # 检查是否有下一页
            has_next = result.get("has_next_page", False)
            print(f"是否有下一页: {has_next}")
            
            if not has_next:
                print("没有更多页面")
                break
                
            # 获取下一页的游标
            next_cursor = result.get("next_cursor", "")
            if not next_cursor:
                print("没有获取到下一页游标")
                break
                
            cursor = next_cursor
            print(f"已获取第 {page_count} 页回复，累计 {len(all_replies)} 条")
            
        print(f"完成获取，共 {len(all_replies)} 条回复，获取了 {page_count} 页")
        
        return {
            "replies": all_replies,
            "total_count": len(all_replies),
            "pages_fetched": page_count,
            "status": "success"
        }
    
    def advanced_search(self, query: str, query_type: str = "Latest", cursor: str = "") -> Dict:
        """
        高级搜索推文
        
        Args:
            query: 搜索查询字符串，例如 "AI" OR "Twitter" from:elonmusk
            query_type: 搜索类型，"Latest"或"Top"
            cursor: 分页游标，第一页为空字符串
            
        Returns:
            包含搜索结果的字典
        """
        url = f"{BASE_URL}/twitter/tweet/advanced_search"
        params = {
            "query": query,
            "queryType": query_type
        }
        
        if cursor:
            params["cursor"] = cursor
        
        response = requests.get(url, headers=self.headers, params=params)
        return response.json()
    
    def extract_addresses_from_tweet_and_replies(self, tweet_id_or_url: str, get_all_replies: bool = True) -> Dict:
        """
        从指定的推文及其回复中提取加密货币地址
        
        Args:
            tweet_id_or_url: 推文ID或Twitter链接
            get_all_replies: 是否获取所有回复（True）或仅第一页回复（False）
            
        Returns:
            包含结果统计信息的字典
        """
        # 从URL中提取tweet_id（如果提供的是URL）
        tweet_id = extract_tweet_id(tweet_id_or_url) or tweet_id_or_url
        
        if not tweet_id or not tweet_id.isdigit():
            return {"status": "error", "message": "无效的tweet_id或URL"}
        
        # 清空之前的地址数据
        self.addresses_data = {}
        
        result_stats = {
            "tweet_id": tweet_id,
            "original_tweet_processed": False,
            "replies_processed": 0,
            "addresses_found": 0,
            "addresses_by_type": {}
        }
        
        # 1. 获取原始推文内容并提取其中的加密货币地址
        tweet_data = self.get_tweets_by_ids([tweet_id])
        
        if tweet_data.get("status") == "success" and "tweets" in tweet_data and len(tweet_data["tweets"]) > 0:
            original_tweet = tweet_data["tweets"][0]
            
            # 格式化推文数据以便提取地址
            formatted_tweet = {
                "author": {
                    "id": original_tweet.get("author", {}).get("id", ""),
                    "userName": original_tweet.get("author", {}).get("userName", ""),
                    "name": original_tweet.get("author", {}).get("name", ""),
                    "description": original_tweet.get("author", {}).get("description", "")
                },
                "text": original_tweet.get("text", ""),
                "twitterUrl": original_tweet.get("url", f"https://twitter.com/i/web/status/{tweet_id}")
            }
            
            # 提取地址
            tweet_text = formatted_tweet["text"]
            author_desc = formatted_tweet["author"].get("description", "")
            
            # 合并文本以查找地址
            addresses_in_tweet = extract_crypto_addresses(tweet_text)
            addresses_in_author = extract_crypto_addresses(author_desc)
            
            all_addresses_in_original = []
            address_set = set()
            
            # 合并去重
            for addr in addresses_in_tweet + addresses_in_author:
                if addr["address"] not in address_set:
                    address_set.add(addr["address"])
                    all_addresses_in_original.append(addr)
            
            if all_addresses_in_original:
                formatted_tweet["addresses"] = all_addresses_in_original
                
                # 保存到内存
                self._add_address_info(formatted_tweet)
                
                # 更新统计信息
                result_stats["original_tweet_processed"] = True
                result_stats["addresses_found"] += len(all_addresses_in_original)
                
                # 按类型统计
                for addr in all_addresses_in_original:
                    addr_type = addr["type"]
                    if addr_type not in result_stats["addresses_by_type"]:
                        result_stats["addresses_by_type"][addr_type] = 0
                    result_stats["addresses_by_type"][addr_type] += 1
            
            else:
                result_stats["original_tweet_processed"] = True
        
        # 2. 获取推文回复并提取加密货币地址
        if get_all_replies:
            # 获取所有回复
            all_replies = self.get_all_tweet_replies(tweet_id, filter_fields=True)
            result_stats["replies_processed"] = all_replies["total_count"]
        else:
            # 仅获取第一页回复
            replies = self.get_tweet_replies(tweet_id, filter_fields=True)
            if "tweets" in replies:
                result_stats["replies_processed"] = len(replies["tweets"])
        
        # 3. 统计最终地址
        result_stats["addresses_total"] = len(self.addresses_data)
        
        # 重新统计所有类型
        type_counts = {}
        for addr, data in self.addresses_data.items():
            addr_type = data.get("type", "未知")
            if addr_type not in type_counts:
                type_counts[addr_type] = 0
            type_counts[addr_type] += 1
        
        result_stats["all_addresses_by_type"] = type_counts
        
        return result_stats

def save_to_json(data, filename=None, prefix="twitter_data", tweet_id=None):
    """
    将数据保存到JSON文件
    
    Args:
        data: 要保存的数据
        filename: 文件名(可选)，如不提供则自动生成
        prefix: 文件名前缀
        tweet_id: 推文ID，用于生成默认文件名
        
    Returns:
        保存的文件路径
    """
    if not filename:
        # 优先使用推文ID作为文件名
        if tweet_id:
            filename = f"{tweet_id}.json"
        else:
            # 如果没有推文ID，则使用时间戳
            timestamp = int(time.time())
            filename = f"{prefix}_{timestamp}.json"
    
    filepath = os.path.join(SAVE_DIR, filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return filepath
    except Exception as e:
        print(f"保存数据失败: {e}")
        return None

def save_to_csv(data, filename=None, prefix="twitter_data", tweet_id=None):
    """
    将地址数据保存到CSV文件，处理引号和特殊字符
    """
    if not filename:
        # 优先使用推文ID作为文件名
        if tweet_id:
            filename = f"{tweet_id}.csv"
        else:
            timestamp = int(time.time())
            filename = f"{prefix}_{timestamp}.csv"
    
    filepath = os.path.join(SAVE_DIR, filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8', newline='') as f:
            fieldnames = ['address', 'type', 'author_id', 'author_name', 'author_username', 
                         'author_description', 'text', 'twitter_url']
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            
            for addr, info in data.items():
                addr_type = info.get('type', 'UNKNOWN')
                
                for mention in info.get('mentions', []):
                    author = mention.get('author', {})
                    
                    # 处理字段中的特殊字符，确保CSV格式正确
                    # CSV模块会自动处理引号，但我们需要清理其他可能影响格式的字符
                    row = {
                        'address': addr,
                        'type': addr_type,
                        'author_id': author.get('id', ''),
                        'author_name': _clean_text(author.get('name', '')),
                        'author_username': author.get('userName', ''),
                        'author_description': _clean_text(author.get('description', '')),
                        'text': _clean_text(mention.get('text', '')),
                        'twitter_url': mention.get('twitterUrl', '')
                    }
                    
                    writer.writerow(row)
        
        return filepath
    except Exception as e:
        print(f"保存CSV数据失败: {e}")
        return None

def _clean_text(text):
    """清理文本，使其适合CSV格式"""
    if not text:
        return ""
    # 移除换行符和回车符
    text = text.replace('\n', ' ').replace('\r', ' ')
    # CSV模块会处理双引号(通过双重引号)，但为安全起见，我们可以替换其他潜在问题字符
    # 例如移除零宽字符等
    text = re.sub(r'[\u200B-\u200D\uFEFF]', '', text)
    return text

def process_twitter_url(url, output_format='json', output_file=None, prefix="twitter_data"):
    """
    处理Twitter/X URL，提取加密货币地址并导出为指定格式
    
    Args:
        url: Twitter/X推文的URL或ID
        output_format: 输出格式，'json'或'csv'
        output_file: 输出文件名，不指定则自动生成
        prefix: 自动生成文件名时使用的前缀
    
    Returns:
        处理结果统计信息
    """
    # 创建API客户端
    twitter_api = TwitterApiIO()
    
    # 首先验证API有效性
    api_validation = twitter_api.validate_api()
    if not api_validation.get("is_valid", False):
        print(f"API验证失败，无法处理URL: {api_validation.get('message', '未知错误')}")
        return {"status": "error", "message": api_validation.get('message', '未知错误')}
    
    # 打印开始信息
    print(f"\n开始提取推文及其回复中的加密货币地址...")
    
    # 提取推文ID
    tweet_id = extract_tweet_id(url) or url
    
    # 调用API提取地址
    result = twitter_api.extract_addresses_from_tweet_and_replies(url)
    
    # 从内存获取提取的地址数据
    addresses_data = twitter_api.addresses_data
    
    # 根据格式选择导出方式
    if output_format.lower() == 'csv':
        output_path = save_to_csv(addresses_data, output_file, prefix, tweet_id)
        if output_path:
            print(f"\n已将地址数据导出为CSV: {output_path}")
    else:  # json格式
        output_path = save_to_json(addresses_data, output_file, prefix, tweet_id)
        if output_path:
            print(f"\n已将地址数据导出为JSON: {output_path}")
    
    # 附加导出路径到结果
    result['output_file'] = output_path
    
    return result

def print_results(result):
    """
    打印处理结果统计信息
    
    Args:
        result: 处理结果统计信息
    """
    if not result:
        print("处理失败，没有结果")
        return
        
    print(f"\n处理完成! 统计信息:")
    print(f"- 推文ID: {result['tweet_id']}")
    print(f"- 原始推文是否处理: {'是' if result['original_tweet_processed'] else '否'}")
    print(f"- 处理的回复数量: {result['replies_processed']}")
    print(f"- 发现的新地址数量: {result['addresses_found']}")
    
    if "addresses_by_type" in result and result["addresses_by_type"]:
        print("\n本次发现的地址类型分布:")
        for addr_type, count in result["addresses_by_type"].items():
            print(f"- {addr_type}: {count}个")
    
    if "all_addresses_by_type" in result:
        print("\n所有已保存地址的类型分布:")
        for addr_type, count in result["all_addresses_by_type"].items():
            print(f"- {addr_type}: {count}个")
    
    print(f"\n总计找到 {result.get('addresses_total', 0)} 个唯一加密货币地址")

def read_twitter_urls(file_path):
    """
    从文本文件中读取Twitter URL列表
    
    Args:
        file_path: 包含Twitter URL的文本文件路径
        
    Returns:
        URL列表
    """
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # 去除空白字符并跳过空行和注释
                url = line.strip()
                if url and not url.startswith('#'):
                    urls.append(url)
        print(f"从文件 {file_path} 中读取了 {len(urls)} 个Twitter URL")
        return urls
    except Exception as e:
        print(f"读取URL文件失败: {e}")
        return []


def process_batch(urls, output_format='json', output_file=None, prefix="twitter_data"):
    """
    批量处理多个Twitter URL
    
    Args:
        urls: Twitter/X推文URL列表
        output_format: 输出格式，'json'或'csv'
        output_file: 输出文件名，不指定则自动生成
        prefix: 自动生成文件名时使用的前缀
    
    Returns:
        处理结果统计信息的列表
    """
    # 创建API客户端
    twitter_api = TwitterApiIO()
    
    # 首先验证API有效性
    api_validation = twitter_api.validate_api()
    if not api_validation.get("is_valid", False):
        print(f"API验证失败，无法处理URL: {api_validation.get('message', '未知错误')}")
        return [{"status": "error", "message": api_validation.get('message', '未知错误')}]
    
    results = []
    total_count = len(urls)
    
    # 创建批量处理的摘要文件
    summary_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_file = os.path.join(SAVE_DIR, f"batch_summary_{summary_time}.txt")
    
    with open(summary_file, 'w', encoding='utf-8') as summary:
        summary.write(f"批量处理开始时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        summary.write(f"处理URL总数: {total_count}\n\n")
        summary.write("="*80 + "\n\n")
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{total_count}] 处理URL: {url}")
            summary.write(f"[{i}/{total_count}] URL: {url}\n")
            
            # 处理单个URL
            try:
                result = process_twitter_url(url, output_format, None, prefix)
                results.append(result)
                
                # 写入摘要信息
                if result.get("status") == "error":
                    summary.write(f"  状态: 失败 - {result.get('message', '未知错误')}\n")
                else:
                    summary.write(f"  状态: 成功\n")
                    summary.write(f"  找到地址数: {result.get('addresses_total', 0)}\n")
                    if "output_file" in result:
                        summary.write(f"  输出文件: {result['output_file']}\n")
                    
                    # 写入地址类型分布
                    if "all_addresses_by_type" in result:
                        summary.write("  地址类型分布:\n")
                        for addr_type, count in result["all_addresses_by_type"].items():
                            summary.write(f"    - {addr_type}: {count}个\n")
                
                summary.write("\n")
                
                # 每处理一个URL就刷新文件，确保数据被写入
                summary.flush()
                
                # 添加一些间隔，避免API请求过于频繁
                if i < total_count:
                    time.sleep(2)
                    
            except Exception as e:
                error_msg = f"处理URL时出错: {str(e)}"
                print(error_msg)
                summary.write(f"  状态: 出错 - {error_msg}\n\n")
                results.append({"status": "error", "message": error_msg, "url": url})
                
        # 写入总结
        summary.write("\n" + "="*80 + "\n\n")
        summary.write(f"批量处理结束时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        successful = sum(1 for r in results if r.get("status") != "error")
        summary.write(f"成功处理: {successful}/{total_count}\n")
        summary.write(f"失败处理: {total_count - successful}/{total_count}\n")
    
    print(f"\n批量处理完成！摘要已保存至: {summary_file}")
    return results


def parse_arguments():
    """
    解析命令行参数
    
    Returns:
        解析后的参数
    """
    parser = argparse.ArgumentParser(description='从Twitter/X推文中提取加密货币地址')
    
    # 创建互斥组，用户可以提供url或默认使用file参数
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--url', help='Twitter/X推文的URL或ID')
    parser.add_argument('--file', '-f', default='twitter_urls.txt',
                      help='包含Twitter URL的文本文件路径 (默认: twitter_urls.txt)')
    
    parser.add_argument('--format', choices=['json', 'csv'], default='csv', 
                       help='导出格式: json或csv (默认: csv)')
    parser.add_argument('--output', '-o', help='输出文件名，不指定则自动生成')
    parser.add_argument('--prefix', default='twitter_data', 
                       help='输出文件名前缀，只在自动生成文件名时使用')
    
    return parser.parse_args()

def main():
    """
    主函数
    """
    # 创建API客户端
    twitter_api = TwitterApiIO()
    # result = twitter_api.advanced_search("drop you Monad address blow")
    # print(result)
    
    # exit(0)
    
    # 首先验证API有效性
    api_validation = twitter_api.validate_api()
    if not api_validation.get("is_valid", False):
        print(f"API验证失败，无法继续执行程序,可能欠费，请去 https://twitterapi.io/dashboard 充值")
        return 1
    
    # 解析命令行参数
    args = parse_arguments()
    
    if args.url:
        # 单个URL处理模式
        result = process_twitter_url(
            args.url, 
            output_format=args.format, 
            output_file=args.output, 
            prefix=args.prefix
        )
        
        # 打印结果
        print_results(result)
    else:
        # 批量处理模式 - 默认使用file参数指定的文件
        urls = read_twitter_urls(args.file)
        if not urls:
            print(f"没有找到有效的URL，请检查文件 {args.file} 的内容")
            return 1
            
        # 处理批量URL
        results = process_batch(
            urls, 
            output_format=args.format, 
            output_file=args.output, 
            prefix=args.prefix
        )
        
        # 打印批量处理统计
        print(f"\n总批量处理统计:")
        print(f"- 成功处理: {sum(1 for r in results if r.get('status') != 'error')}/{len(urls)}")
        print(f"- 失败处理: {sum(1 for r in results if r.get('status') == 'error')}/{len(urls)}")
    
    return 0

# 使用示例
if __name__ == "__main__":
    sys.exit(main())



