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
```bash
