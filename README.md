For python3.6
### Deploy
```bash
git clone https://github.com/max2max/ss-aead shadowsocks
chmod +x ./shadowsocks/*.sh

cd shadowsocks
./run.sh
./logrun.sh
./stop.sh

# 监控需要psutil模块
pip3.6 install psutil
# mysql连接需要cymysql模块
pip3.6 install cymysql

# 切换分支
git checkout aead
# 重置/初始化分支，等于将一切修改归0
git reset --hard origin/aead
# 更新代码，当前分支
git pull origin
# 更新所有分支的代码
git pull

cd shadowsocks
rm -rf nettest*
wget https://raw.githubusercontent.com/max2max/ss-aead/aead/nettest_thread.py
killall python3.6
nohup /usr/local/bin/python3.6 /root/shadowsocks/server.py m >> /dev/null 2>&1 &
```
