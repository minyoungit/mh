#!/bin/sh

OS=`uname`
HOSTNAME=`hostname`
LANG=C
export LANG

clear
sleep 1

echo " "
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "*                                          *"
echo "*       Copyright 2020 ROIS Co. Ltd.       *"
echo "*           All right Reserved             *"
echo "*                                          *"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo " "

echo "======== Assessment start time ========" >> $HOSTNAME.txt 2>&1
echo `date` >> $HOSTNAME.txt 2>&1
chmod 400 $HOSTNAME.txt

echo "Information gathering........"
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1
echo "===== System Information Query Start =====" >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1
chmod 400 $HOSTNAME-SystemInformation.txt

echo "# uname -a " >> $HOSTNAME-SystemInformation.txt 2>&1
uname -a >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

if [ $OS = "HP-UX" ]
then
	echo "ifconfig `lanscan -v | grep "lan" | awk -F' ' '{print $5}' | uniq`" >> $HOSTNAME-SystemInformation.txt 2>&1
	ifconfig `lanscan -v | grep "lan" | awk -F' ' '{print $5}' | uniq` >> $HOSTNAME-SystemInformation.txt 2>&1
else
	echo "# ifconfig -a " >> $HOSTNAME-SystemInformation.txt 2>&1
	ifconfig -a >> $HOSTNAME-SystemInformation.txt 2>&1
fi
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

echo "## Process Information ##" >> $HOSTNAME-SystemInformation.txt 2>&1
ps -ef | grep -v grep | grep -v ps | cut -c47-80 | sort | uniq > tmp0.txt 2>&1
cat tmp0.txt >> $HOSTNAME-SystemInformation.txt 2>&1
rm tmp0.txt
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

echo "# netstat -an " >> $HOSTNAME-SystemInformation.txt 2>&1
netstat -an >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

echo "# netstat -rn " >> $HOSTNAME-SystemInformation.txt 2>&1
netstat -rn >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

echo "# ps -ef " >> $HOSTNAME-SystemInformation.txt 2>&1
ps -ef | grep -v grep >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

echo "# ps -ef | egrep httpd|sendmail|named|nfsd|dmi|snmpd " >> $HOSTNAME-SystemInformation.txt 2>&1
ps -ef | egrep "httpd|sendmail|named|nfsd|dmi|snmpd" | grep -v grep>> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

echo "# env " >> $HOSTNAME-SystemInformation.txt 2>&1
env >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1

echo "# rpm -qa | sort " >> $HOSTNAME-SystemInformation.txt 2>&1
rpm -qa 2> /dev/null | sort >> $HOSTNAME-SystemInformation.txt 2>&1

echo " " >> $HOSTNAME-SystemInformation.txt 2>&1
echo "===== System Information Query End ======"
echo "===== System Information Query End ======" >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1


echo "################### 1. Account Management ###################"
echo "################### 1. 계정관리 ###################" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " [SU1-01]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "####################          SU1-01 root 계정의 원격 접속을 제한하고 있는가?         ######################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

badCount=0
echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ `cat /etc/services | awk '$1=="telnet" {print $2}' | grep "tcp" | awk -F "/" '{print $1}' | wc -l` -gt 0 ]   # wc 앞까지는 23 / wc -l로 행의 존재 판단
then
	echo "[ Telnet Service 확인 ]" >> $HOSTNAME.txt 2>&1
	port=`cat /etc/services |awk '$1=="telnet" {print $2}' |grep "tcp" | awk -F "/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp" >> $HOSTNAME.txt 2>&1
		echo "Telnet Service가 활성화되어있음" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[ /etc/securetty 설정 ]" >> $HOSTNAME.txt 2>&1
		if [ `cat /etc/securetty | grep "pts" | wc -l` -gt 0 ]
		then
			cat /etc/securetty | grep -i "pts" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "/etc/securetty 파일에 pts/x 설정이 존재하여 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			badCount=$(($badCount+1))
		else
			echo "/etc/securetty 파일에 pts/0~pts/x 설정이 존재하지않아 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "Telnet Service가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
	fi
fi

if [ `cat /etc/services |awk '$1=="ssh" {print $2}' |grep "tcp" | awk -F "/" '{print $1}' | wc -l` -gt 0 ]    # wc 앞까지는 22 / wc -l로 행의 존재 판단
then
	echo "[ SSH Service 확인 ]" >> $HOSTNAME.txt 2>&1
	port2=`cat /etc/services |awk '$1=="ssh" {print $2}' |grep "tcp" | awk -F "/" '{print $1}'`
	if [ `netstat -na | grep ":$port2 " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port2 " | grep -i "^tcp" >> $HOSTNAME.txt 2>&1
		echo "SSH Service가 활성화되어 있음" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[ /etc/ssh/sshd_config 설정 ]" >> $HOSTNAME.txt 2>&1
		if [ `cat /etc/ssh/sshd_config | grep -G "^PermitRootLogin" | wc -l` -gt 0 ]
		then
			cat /etc/ssh/sshd_config | grep -G "^PermitRootLogin" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			if [ `cat /etc/ssh/sshd_config | grep -G "^PermitRootLogin" | awk '$1=="PermitRootLogin" {print $2}' | egrep -i "no" | wc -l ` -gt 0 ]
			then
				echo "/etc/ssh/sshd_config 파일에 PermitRootLogin 설정이 no로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
			else
				echo "/etc/ssh/sshd_config 파일에 PermitRootLogin 설정이 yes로 되어있어 취약" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				badCount=$(($badCount+1))
			fi
		else
			badCount=$(($badCount+1))
			echo "/etc/ssh/sshd_config 파일에 PermitRootLogin 설정이 존재하지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "SSH Service가 비활성화 되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
	fi
fi

pam=`cat /etc/pam.d/login | grep -i "/lib/security/pam_securetty.so"`

if [ $badCount -eq 0 ] && [ `echo $pam | grep -v "^$" | wc -l` -gt 0 ]	# grep -v "^$" : 공백 제외 / wc -l : 라인수 세기
then
	echo "[ /etc/pam.d/login 설정 ]" >> $HOSTNAME.txt 2>&1
    cat /etc/pam.d/login | grep "/lib/security/pam_securetty.so" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `echo $pam | awk '{print $1}'` = "auth" ] && [ `echo $pam | awk '{print $2}'` = "required" ] && [ `echo $pam | awk '{print $3}'` = "/lib/security/pam_securetty.so" ]
	then
		echo "/etc/pam.d/login 파일에 root 원격 접속을 제한하고있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-01] 양호 - SU1.01-root 계정의 원격 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/pam.d/login 파일에 root 원격 접속을 제한하지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-01] 취약 - SU1.01-root 계정의 원격 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-01] 취약 - SU1.01-root 계정의 원격 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU1-01] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset badCount
unset port1
unset port2
unset pam


echo " [SU1-02]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "####################          SU1-02 패스워드 복잡도 설정이 적절하게 되어 있는가?         ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ -f /etc/pam.d/common-password ]
then
	if [ `grep -v "#" /etc/pam.d/common-password 2> /dev/null | grep "minlen" | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		echo "[ 최소 길이 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/pam.d/common-password | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		MINLEN=`grep "minlen" /etc/pam.d/common-password | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | awk -F "=" '{print $2}'`
	elif [ `grep "minlen" /etc/security/pwquality.conf 2> /dev/null | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | grep -v "#" | wc -l` -eq 1 ]
	then
		echo "[ 최소 길이 설정(etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/security/pwquality.conf | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		MINLEN=`grep "minlen" /etc/security/pwquality.conf | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | awk -F "=" '{print $2}'`
	else
		echo "[ 최소 길이 설정 ]" >> $HOSTNAME.txt 2>&1
		echo "minlen(최소길이) 미설정" >> $HOSTNAME.txt 2>&1
		MINLEN=0
	fi
	echo " " >> $HOSTNAME.txt 2>&1

	if [ `grep -v "#" /etc/pam.d/common-password 2> /dev/null | grep "ucredit" | sed -r 's/.*(ucredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		if [ `grep "ucredit" /etc/pam.d/common-password 2> /dev/null | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
		then
			echo "[ 영대문자 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "ucredit" /etc/pam.d/common-password | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ucredit(영대문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			UCREDIT=1
		else
			echo "[ 영대문자 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "ucredit" /etc/pam.d/common-password | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ucredit(영대문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			UCREDIT=0
		fi
	elif [ `grep -v "#" /etc/security/pwquality.conf 2> /dev/null | grep "ucredit" | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		if [ `grep "ucredit" /etc/security/pwquality.conf 2> /dev/null | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
		then
			echo "[ 영대문자 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "ucredit" /etc/security/pwquality.conf | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ucredit(영대문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			UCREDIT=1
		else
			echo "[ 영대문자 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "ucredit" /etc/security/pwquality.conf | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ucredit(영대문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			UCREDIT=0
		fi
	else
		echo "[ 영대문자 설정 ]" >> $HOSTNAME.txt 2>&1
		echo "ucredit(영대문자) 미설정" >> $HOSTNAME.txt 2>&1
		UCREDIT=0
	fi
	echo " " >> $HOSTNAME.txt 2>&1

	if [ `grep -v "#" /etc/pam.d/common-password | grep "lcredit" | sed -r 's/.*(lcredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		if [ `grep "lcredit" /etc/pam.d/common-password | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
		then
			echo "[ 영소문자 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "lcredit" /etc/pam.d/common-password | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "lcredit(영소문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			LCREDIT=1
		else
			echo "[ 영소문자 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "lcredit" /etc/pam.d/common-password | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "lcredit(영소문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			LCREDIT=0
		fi
	elif [ `grep -v "#" /etc/security/pwquality.conf 2> /dev/null | grep "lcredit" | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		if [ `grep "lcredit" /etc/security/pwquality.conf | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
		then
			echo "[ 영소문자 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "lcredit" /etc/security/pwquality.conf | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "lcredit(영소문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			LCREDIT=1
		else
			echo "[ 영소문자 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "lcredit" /etc/security/pwquality.conf | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "lcredit(영소문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			LCREDIT=0
		fi
	else
		echo "[ 영소문자 설정 ]" >> $HOSTNAME.txt 2>&1
		echo "lcredit(영소문자) 미설정" >> $HOSTNAME.txt 2>&1
		LCREDIT=0
	fi
	echo " " >> $HOSTNAME.txt 2>&1

	if [ `grep -v "#" /etc/pam.d/common-password | grep "dcredit" | sed -r 's/.*(dcredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		if [ `grep "dcredit" /etc/pam.d/common-password | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
		then
			echo "[ 숫자 포함 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "dcredit" /etc/pam.d/common-password | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "dcredit(숫자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			DCREDIT=1
		else
			echo "[ 숫자 포함 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "dcredit" /etc/pam.d/common-password | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "dcredit(숫자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			DCREDIT=0
		fi
	elif [ `grep -v "#" /etc/security/pwquality.conf 2> /dev/null | grep "dcredit" | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		if [ `grep "dcredit" /etc/security/pwquality.conf | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ]
		then
			echo "[ 숫자 포함 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "dcredit" /etc/security/pwquality.conf | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "dcredit(숫자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			DCREDIT=1
		else
			echo "[ 숫자 포함 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "dcredit" /etc/security/pwquality.conf | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "dcredit(숫자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			DCREDIT=0
		fi
	else
		echo "[ 숫자 포함 설정 ]" >> $HOSTNAME.txt 2>&1
		echo "dcredit(숫자) 미설정" >> $HOSTNAME.txt 2>&1
		DCREDIT=0
	fi
	echo " " >> $HOSTNAME.txt 2>&1

	if [ ` grep -v "#" /etc/pam.d/common-password | grep "ocredit" | sed -r 's/.*(ocredit=-1+)(.*)/\1/' |wc -l` -eq 1 ]
	then
		if [ `grep "ocredit" /etc/pam.d/common-password | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
		then
			echo "[ 특수문자 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "ocredit" /etc/pam.d/common-password | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ocredit(특수문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			OCREDIT=1
		else
			echo "[ 특수문자 설정(/etc/pam.d/common-password) ]" >> $HOSTNAME.txt 2>&1
			grep "ocredit" /etc/pam.d/common-password | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ocredit(특수문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			OCREDIT=0
		fi
	elif [ `grep -v "#" /etc/security/pwquality.conf 2> /dev/null | grep "ocredit" | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' | wc -l` -eq 1 ]
	then
		if [ `grep "ocredit" /etc/security/pwquality.conf | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ]
		then
			echo "[ 특수문자 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "ocredit" /etc/security/pwquality.conf | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ocredit(특수문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
			OCREDIT=1
		else
			echo "[ 특수문자 설정(/etc/security/pwquality.conf) ]" >> $HOSTNAME.txt 2>&1
			grep "ocredit" /etc/security/pwquality.conf | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			echo "ocredit(특수문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			OCREDIT=0
		fi
	else
		echo "[ 특수문자 설정 ]" >> $HOSTNAME.txt 2>&1
		echo "ocredit(특수문자) 미설정" >> $HOSTNAME.txt 2>&1
		OCREDIT=0
	fi
	echo " " >> $HOSTNAME.txt 2>&1

else
	if [ `cat /etc/security/pwquality.conf 2> /dev/null | wc -l` -gt 0 ]
	then
		echo "[ /etc/security/pwquality.conf 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `grep -v "#" /etc/security/pwquality.conf | grep "minlen" | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			echo "[ 최소 길이 설정 ]" >> $HOSTNAME.txt 2>&1
			grep "minlen" /etc/security/pwquality.conf | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			MINLEN=`grep "minlen" /etc/security/pwquality.conf | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | awk -F "=" '{print $2}'`
		else
			echo "[ 최소 길이 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "minlen(최소길이) 미설정" >> $HOSTNAME.txt 2>&1
			MINLEN=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/security/pwquality.conf | grep "ucredit" | sed -r 's/.*(ucredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			if [ `grep "ucredit" /etc/security/pwquality.conf | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 영대문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ucredit" /etc/security/pwquality.conf | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ucredit(영대문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				UCREDIT=1
			else
				echo "[ 영대문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ucredit" /etc/security/pwquality.conf | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ucredit(영대문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				UCREDIT=0
			fi
		else
			echo "[ 영대문자 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "ucredit(영대문자) 미설정" >> $HOSTNAME.txt 2>&1
			UCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/security/pwquality.conf | grep "lcredit" | sed -r 's/.*(lcredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			if [ `grep "lcredit" /etc/security/pwquality.conf | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 영소문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "lcredit" /etc/security/pwquality.conf | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "lcredit(영소문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				LCREDIT=1
			else
				echo "[ 영소문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "lcredit" /etc/security/pwquality.conf | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "lcredit(영소문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				LCREDIT=0
			fi
		else
			echo "[ 영소문자 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "lcredit(영소문자) 미설정" >> $HOSTNAME.txt 2>&1
			LCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/security/pwquality.conf | grep "dcredit" | sed -r 's/.*(dcredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			if [ `grep "dcredit" /etc/security/pwquality.conf | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 숫자 포함 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "dcredit" /etc/security/pwquality.conf | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "dcredit(숫자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				DCREDIT=1
			else
				echo "[ 숫자 포함 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "dcredit" /etc/security/pwquality.conf | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "dcredit(숫자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				DCREDIT=0
			fi
		else
			echo "[ 숫자 포함 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "dcredit(숫자) 미설정" >> $HOSTNAME.txt 2>&1
			DCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/security/pwquality.conf | grep "ocredit" | sed -r 's/.*(ocredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			if [ `grep "ocredit" /etc/security/pwquality.conf | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 특수문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ocredit" /etc/security/pwquality.conf | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ocredit(특수문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				OCREDIT=1
			else
				echo "[ 특수문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ocredit" /etc/security/pwquality.conf | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ocredit(특수문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				OCREDIT=0
			fi
		else
			echo "[ 특수문자 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "ocredit(특수문자) 미설정" >> $HOSTNAME.txt 2>&1
			OCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

	else
		echo "[ /etc/pam.d/system-auth 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `grep -v "#" /etc/pam.d/system-auth | grep "minlen" | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			echo "[ 최소 길이 설정 ]" >> $HOSTNAME.txt 2>&1
			grep "minlen" /etc/pam.d/system-auth | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
			MINLEN=`grep "minlen=" /etc/pam.d/system-auth | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | awk -F "=" '{print $2}'`
		else
			echo "[ 최소 길이 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "minlen(최소길이) 미설정" >> $HOSTNAME.txt 2>&1
			MINLEN=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/pam.d/system-auth | grep "ucredit" | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' | wc -l` -eq 1 ] # 주석이 포함되지 않은 ucredit이 존재하는지 확인
		then
			if [ `grep "ucredit" /etc/pam.d/system-auth | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 영대문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ucredit" /etc/pam.d/system-auth | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ucredit(영대문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				UCREDIT=1
			else
				echo "[ 영대문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ucredit" /etc/pam.d/system-auth | sed -r 's/.*(ucredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ucredit(영대문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				UCREDIT=0
			fi
		else
			echo "[ 영대문자 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "ucredit(영대문자) 미설정" >> $HOSTNAME.txt 2>&1
			UCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/pam.d/system-auth | grep "lcredit" | sed -r 's/.*(lcredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			if [ `grep "lcredit" /etc/pam.d/system-auth | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 영소문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "lcredit" /etc/pam.d/system-auth | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "lcredit(영소문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				LCREDIT=1
			else
				echo "[ 영소문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "lcredit" /etc/pam.d/system-auth | sed -r 's/.*(lcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "lcredit(영소문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				LCREDIT=0
			fi
		else
			echo "[ 영소문자 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "lcredit(영소문자) 미설정" >> $HOSTNAME.txt 2>&1
			LCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/pam.d/system-auth | grep "dcredit" | sed -r 's/.*(dcredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			if [ `grep "dcredit" /etc/pam.d/system-auth | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 숫자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "dcredit" /etc/pam.d/system-auth | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "dcredit(숫자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				DCREDIT=1
			else
				echo "[ 숫자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "dcredit" /etc/pam.d/system-auth | sed -r 's/.*(dcredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "dcredit(숫자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				DCREDIT=0
			fi
		else
			echo "[ 숫자 포함 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "dcredit(숫자) 미설정" >> $HOSTNAME.txt 2>&1
			DCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1

		if [ `grep -v "#" /etc/pam.d/system-auth | grep "ocredit" | sed -r 's/.*(ocredit=-1+)(.*)/\1/' | wc -l` -eq 1 ]
		then
			if [ `grep "ocredit" /etc/pam.d/system-auth | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' | awk -F= '{print $2}'` -eq -1 ] # 참(ucredit이 존재할 경우)
			then
				echo "[ 특수문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ocredi=" /etc/pam.d/system-auth | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ocredit(특수문자) 설정이 -1로 되어있어 양호" >> $HOSTNAME.txt 2>&1
				OCREDIT=1
			else
				echo "[ 특수문자 설정 ]" >> $HOSTNAME.txt 2>&1
				grep "ocredit" /etc/pam.d/system-auth | sed -r 's/.*(ocredit=[-1]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
				echo "ocredit(특수문자) 설정이 -1로 되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				OCREDIT=0
			fi
		else
			echo "[ 특수문자 설정 ]" >> $HOSTNAME.txt 2>&1
			echo "ocredit(특수문자) 미설정" >> $HOSTNAME.txt 2>&1
			OCREDIT=0
		fi
		echo " " >> $HOSTNAME.txt 2>&1
	fi
fi

COMPLEX=`expr $UCREDIT + $LCREDIT + $DCREDIT + $OCREDIT`

if [ $MINLEN -ge 10 ]
then
	if [ $COMPLEX -ge 2 ]
	then
		echo "최소길이 10자리 이상, 조건 2가지 이상 사용하여 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-02] 양호 - SU1.02-패스워드 복잡도 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "최소길이 10자리 이상지만 조건 2가지 이상 사용하지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-02] 취약 - SU1.02-패스워드 복잡도 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	if [ $MINLEN -ge 8 ]
	then
		if [ $COMPLEX -ge 3 ]
		then
			echo "최소길이 8자리 이상, 조건 3가지 이상 사용하여 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU1-02] 양호 - SU1.02-패스워드 복잡도 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "최소길이 8자리 이상이지만, 조건이 3가지 이상 사용하지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU1-02] 취약 - SU1.02-패스워드 복잡도 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "최소길이가 적절하지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-02] 취약 - SU1.02-패스워드 복잡도 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU1-02] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset COMPLEX
unset MINLEN
unset UCREDIT
unset LCREDIT
unset DCREDIT
unset OCREDIT


echo " [SU1-03]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#######################          SU1-03 계정 잠금 임계값 설정이 되어 있는가?         ######################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 계정 임계값 설정 확인 ]" >> $HOSTNAME.txt 2>&1
grep "deny=" /etc/pam.d/common-auth 2> /dev/null | sed -r 's/.*(deny=[0-99]+)(.*)/\1/'  >> $HOSTNAME.txt 2>&1
grep "deny=" /etc/pam.d/system-auth 2> /dev/null | sed -r 's/.*(deny=[0-99]+)(.*)/\1/'  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `grep "deny=" /etc/pam.d/common-auth 2> /dev/null| sed -r 's/.*(deny=[0-99]+)(.*)/\1/' | wc -l` -eq 1 ]
then
	if [ `grep "deny=" /etc/pam.d/common-auth 2> /dev/null| sed -r 's/.*(deny=[0-99]+)(.*)/\1/' | awk -F= '{print $2}'` -le 5 ]
	then
		echo "계정 잠금 임계값이 5 이하로 설정되어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
	 	echo "[SU1-03] 양호 - SU1.03-계정 잠금 임계값 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "계정 잠금 임계값이 5 이하로 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-03] 취약 - SU1.03-계정 잠금 임계값 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
elif [ `grep "deny=" /etc/pam.d/system-auth 2> /dev/null| sed -r 's/.*(deny=[0-99]+)(.*)/\1/' | wc -l` -eq 1 ]
then
	if [ `grep "deny=" /etc/pam.d/system-auth 2> /dev/null| sed -r 's/.*(deny=[0-99]+)(.*)/\1/' | awk -F= '{print $2}'` -le 5 ]
	then
		echo "계정 잠금 임계값이 5 이하로 설정되어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-03] 양호 - SU1.03-계정 잠금 임계값 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "계정 잠금 임계값이 5 이하로 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-03] 취약 - SU1.03-계정 잠금 임계값 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "계정 잠금 임계값 미설정되어있어 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-03] 취약 - SU1.03-계정 잠금 임계값 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU1-03] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU1-04]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#################          SU1-04 패스워드 파일에 대한 보호가 적절하게 되어 있는가?         ##################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/shadow 존재 여부 ]" >> $HOSTNAME.txt 2>&1

if [ -f /etc/shadow ]
then
	ls -l /etc/shadow >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `cat /etc/passwd | awk -F: '{print $2}' | sort -u` = "x" ]
		echo "[ 패스워드 암호화 사용 여부 ]" >> $HOSTNAME.txt 2>&1
		then
			cat /etc/passwd | grep $HOSTNAME >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "패스워드를 암호화 저장(2번째 필드 X)하고 있으므로 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU1-04] 양호 - SU1.04-패스워드 파일에 대한 보호가 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		else
			cat /etc/passwd | grep $HOSTNAME >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "패스워드를 평문 저장(2번째 필드 평문)하고 있으므로 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU1-04] 취약 - SU1.04-패스워드 파일에 대한 보호가 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	ls -l /etc/shadow >> $HOSTNAME.txt 2>&1
	echo "/etc/shadow 파일 존재하지않아 취약" >> $HOSTNAME.txt 2>&1
	echo "[SU1-04] 취약 - SU1.04-패스워드 파일에 대한 보호가 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU1-04] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU1-05]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "################          SU1-05 root 계정과 동일한 UID를 가진 계정이 제거되어 있는가?         ################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ root와 동일한 UID 확인 ]" >> $HOSTNAME.txt 2>&1
awk -F: '$3==0  { print $1 " UID=" $3 }' /etc/passwd >> $HOSTNAME.txt 2>&1
awk -F: '$3==0  { print $1 " UID=" $3 }' /etc/passwd >> UID.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `sed /root/d UID.txt | wc -l` -ne 1 ]
	then
		echo "root와 동일한 UID 발견되지않아 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-05] 양호 - SU1.05-root 계정과 동일한 UID를 가진 계정이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		sed /root/d UID.txt
		echo "root와 동일한 UID 발견되어 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-05] 취약 - SU1.05-root 계정과 동일한 UID를 가진 계정이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm UID.txt


echo " [SU1-06]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#############          SU1-06 인가된 사용자만 root 계정 su를 사용하도록 제한하고 있는가?         ###############"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
SGROUP=`ls -alL /bin/su | awk -F " " '{print $4}'`
SUSER=`cat /etc/group | grep "$SGROUP" | awk -F: '{print $4}' | sed '/^$/d'`

echo "[ --- PAM 미사용하는 경우 --- ]" >> $HOSTNAME.txt 2>&1
echo "[ /bin/su 사용자 그룹 확인 ]" >> $HOSTNAME.txt 2>&1
ls -alL /bin/su >> $HOSTNAME.txt 2>&1

if [ `ls -alL /bin/su | grep ".....-.---*" | wc -l` -eq 1 ]
	then
		echo "사용자그룹 : "$SGROUP >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "파일권한이 4750으로 설정되어 양호" >> $HOSTNAME.txt 2>&1
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "파일권한이 4750으로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/group 내 wheel 그룹 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/group | grep "^wheel" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ --- PAM 사용하는 경우 --- ]" >> $HOSTNAME.txt 2>&1
echo "[ /etc/pam.d/su 확인]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/pam.d/su ]
	then
		cat /etc/pam.d/su >> $HOSTNAME.txt 2>&1
		echo "[ 참고] : 아래와 같이 설정되어 있는지 확인" >> $HOSTNAME.txt 2>&1
		echo "         auth required /lib/security/pam_wheel.so debug group=[사용자 그룹] 또는," >> $HOSTNAME.txt 2>&1
		echo "         auth required /lib/security/ISA/pam_wheel.so use_uid" >> $HOSTNAME.txt 2>&1
		echo "         주석제거되어 있어야 하며, [사용자 그룹]은 보편적으로 wheel을 사용" >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/pam.d/su 없음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[SU1-06] 수동 - SU1.06-인가된 사용자만 root 계정 su를 사용하도록 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU1-06] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset SUSER
unset SGROUP


echo " [SU1-07]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "##################          SU1-07 패스워드 최소 길이 설정이 적절하게 되어 있는가?         ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ -f /etc/pam.d/common-password ]
then
	if [ `grep "minlen" /etc/pam.d/common-password | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | awk -F "=" '{print $2}'` -ge 8 ]
	then
		echo "[ 패스워드 최소 길이 (/etc/pam.d/common-password) 확인 ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/pam.d/common-password | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-07] 양호 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "[ /etc/pam.d/common-password 확인 ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/pam.d/common-password | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-07] 취약 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
elif [ `grep -v "#" /etc/security/pwquality.conf 2> /dev/null | grep "minlen" | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | wc -l` -eq 1 ] # pwquality.conf에 minlen이 설정 되어 있을 때
then
	if [ `grep "minlen" /etc/security/pwquality.conf | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | awk -F "=" '{print $2}'` -ge 8 ]
	then
		echo "[ 패스워드 최소 길이 (/etc/security/pwquality.conf) 확인 ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/security/pwquality.conf | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "패스워드 최소 길이가 8 이상으로 설정되어있어 양호 " >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-07] 양호 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "[ /etc/security/pwquality.conf 확인 ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/security/pwquality.conf | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "패스워드 최소 길이가 8 이상으로 설정되어있지않아 취약 " >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-07] 취약 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
elif [ `grep "minlen" /etc/pam.d/system-auth | grep "minlen" | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | wc -l` -eq 1 ] # system-auth에 minlen이 설정 되어 있을 때
then
	if [ `grep -v "#" /etc/pam.d/system-auth 2> /dev/null | grep "minlen" | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' | awk -F "=" '{print $2}'` -ge 8 ]
	then
		echo "[ 패스워드 최소 길이 (/etc/pam.d/system-auth) 확인 ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/pam.d/system-auth | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "패스워드 최소 길이가 8 이상으로 설정되어있어 양호 " >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-07] 양호 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "[ 패스워드 최소 길이 (/etc/pam.d/system-auth) 확인 ]" >> $HOSTNAME.txt 2>&1
		grep "minlen" /etc/pam.d/system-auth | sed -r 's/.*(minlen=[0-99]+)(.*)/\1/' >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "패스워드 최소 길이가 8 이상으로 설정되어있지않아 취약 " >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-07] 취약 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	if [ `grep ^PASS_MIN_LEN /etc/login.defs | awk '{ print $1 "  " $2 }' | wc -l` -gt 0 ]
	then
		if [ `grep ^PASS_MIN_LEN /etc/login.defs | grep -v "^#" | awk '{ print $2 }'` -ge 8 ]
		then
			echo "[ 패스워드 최소 길이 (/etc/login.defs) 확인 ]" >> $HOSTNAME.txt 2>&1
			grep PASS_MIN_LEN /etc/login.defs >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "패스워드 최소 길이가 8 이상으로 설정되어있어 양호 " >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU1-07] 양호 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "[ 패스워드 최소 길이 (/etc/login.defs) 확인 ]" >> $HOSTNAME.txt 2>&1
			grep PASS_MIN_LEN /etc/login.defs >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "패스워드 최소 길이가 8 이상으로 설정되어있지않아 취약 " >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU1-07] 취약 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "패스워드 최소 길이가 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-07] 취약 - SU1.07-패스워드 최소 길이 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU1-07] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU1-08]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#################          SU1-08 패스워드 최대 사용기간 설정이 적절하게 되어 있는가?         #################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ root 그룹 내 사용자의 마지막 패스워드 변경 일자 확인 ]" >> $HOSTNAME.txt 2>&1
if [ `cat /etc/group | grep -i "root" | awk -F: '{print $4}' | grep -v "^$" | wc -l` -eq 1 ]
then
	PW_CHECK=`cat /etc/group | grep -i "root" | awk -F: '{print $4}' | sed 's/\,/\n/g'` >> ChangePW.txt # 세로로 파일로 저장

	for LastPW in $PW_CHECK
	do
		echo "계정명 : $LastPW" >> $HOSTNAME.txt 2>&1
		chage -l $LastPW | grep "Last password change" >> $HOSTNAME.txt 2>&1
	done
	rm ChangePW.txt
else
	echo "root 그룹 내 사용자가 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ 패스워드 최대 사용기간 설정 확인 (/etc/login.defs) ]" >> $HOSTNAME.txt 2>&1
grep ^PASS_MAX_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `grep ^PASS_MAX_DAYS /etc/login.defs | grep -v "^#" | wc -l` -gt 0 ]
	then
	if [ `grep ^PASS_MAX_DAYS /etc/login.defs | grep -v "^#" | awk '{ print $2 }'` -le 90 ]
	then
		echo "패스워드 최대 사용기간이 90일 보다 작게 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-08] 양호 - SU1.08-패스워드 최대 사용기간 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "패스워드 최대 사용기간이 90일 보다 크게 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-08] 취약 - SU1.08-패스워드 최대 사용기간 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "패스워드 최대 사용기간 미설정" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-08] 취약 - SU1.07-패스워드 최대 사용기간 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi
echo "[SU1-08] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset PW_CHECK
unset LASTPW


echo " [SU1-09]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#################          SU1-09 패스워드 최소 사용기간 설정이 적절하게 되어 있는가?         #################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 패스워드 최소 사용기간 설정 확인 ]" >> $HOSTNAME.txt 2>&1
grep ^PASS_MIN_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `grep ^PASS_MIN_DAYS /etc/login.defs | grep -v "^#" | wc -l` -gt 0 ]
then
	if [ `grep ^PASS_MIN_DAYS /etc/login.defs | grep -v "^#" | awk '{ print $2 }'` -eq 1 ]
	then
		echo "패스워드 최소 사용기간이 1일 이상으로 설정되어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-09] 양호 - SU1.09-패스워드 최소 사용기간 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "패스워드 최소 사용기간이 1일 이상으로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-09] 취약 - SU1.09-패스워드 최소 사용기간 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "패스워드 최소 사용기간이 미설정되어 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-09] 취약 - SU1.09-패스워드 최대 사용기간 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU1-09] END" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU1-10]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#######################             SU1-10 불필요한 계정이 제거되어 있는가?             #####################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ Default 계정 확인 ]" >> $HOSTNAME.txt 2>&1
if [ `cat /etc/passwd | egrep "adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid" | wc -l` -eq 0 ]
	then
		echo "Default 계정 존재하지않음" >> $HOSTNAME.txt 2>&1
	else
		cat /etc/passwd | egrep "adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "Default 계정 존재"  >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 수면 계정 확인 ]" >> $HOSTNAME.txt 2>&1
echo "[ lastlog 명령어 ]" >> $HOSTNAME.txt 2>&1
lastlog 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 로그인 실패 기록 확인]" >> $HOSTNAME.txt 2>&1
echo "[ /var/log/secure ]" >> $HOSTNAME.txt 2>&1
if [ `cat /var/log/secure 2> /dev/null | grep "failed" | wc -w` -ge 1 ]
then
	cat /var/log/secure 2> /dev/null | grep "failed" | sort >> $HOSTNAME.txt
	echo " " >> $HOSTNAME.txt 2>&1
	echo "원격 접속이 가능한 쉘이 부여된 계정[UID500이상]을 중점적으로 확인한다." >> $HOSTNAME.txt 2>&1
else
	echo "원격 접속 실패 기록이 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[SU1-10] 수동 - SU1.10-불필요한 계정이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU1-10] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU1-11]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "###############             SU1-11 관리자 그룹에 최소한의 계정만이 포함되어 있는가?             #################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/group 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/group | grep "root:" >> $HOSTNAME.txt 2>&1
if [ `cat /etc/group | grep "root:" | awk -F: '{print $4}' | wc -w` -ge 1 ]
	then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "담당자와 Interview를 진행하여 관리자 그룹에 포함된 계정이 타당한지 체크" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-11] 수동 - SU1.11-관리자 그룹에 최소한의 계정만이 포함되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "root 그룹에 계정이 존재하지 않으므로 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-11] 양호 - SU1.11-관리자 그룹에 최소한의 계정만이 포함되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU1-11] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU1-12]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#################             SU1-12 계정이 존재하지 않는 GID가 제거되어 있는가?             ##################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/group 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/group | sort >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/passwd 확인 ]" >> $HOSTNAME.txt 2>&1
awk -F: '{ print $1 " -> GID=" $4 }' /etc/passwd | sort >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ CHECK]: 1. 존재하지 않는 계정에 GID 설정을 했을 경우 취약" >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 2. 구성원이 존재하지 않는 그룹이 존재하면 취약" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[SU1-12] 수동 - SU1.12-계정이 존재하지 않는 GID가 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU1-12] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU1-13]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "##############             SU1-13 동일한 UID로 설정된 사용자 계정이 제거되어 있는가?             ################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 중복된 UID 출력 ]" >> $HOSTNAME.txt 2>&1
awk -F: '{print $1 " = " $3}' /etc/passwd >> uid_same.txt
awk '{ id = $3 + 0; ++hits[id]; if (hits[id] == 1) { first[id] = $0; }  else { if ( hits[id] == 2) print first[id]; print; } }' uid_same.txt  >> $HOSTNAME.txt 2>&1

if [ -f uid_same.txt ]
then
	if [ `awk -F: '{print $1 " = " $3}' /etc/passwd | awk '{print $3}' | sort | uniq -d | wc -l` -ge 1 ]
	then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "동일한 UID가 1개 이상이므로 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-13] 취약 - SU1.13-동일한 UID로 설정된 사용자 계정이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
	elif [ `awk -F: '{print $1 " = " $3}' /etc/passwd | awk '{print $3}' | sort | uniq -d | wc -l` -eq 0 ]
	then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "동일한 UID가 존재하지 않으므로 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-13] 양호 - SU1.13-동일한 UID로 설정된 사용자 계정이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-13] 수동 - SU1.13-동일한 UID로 설정된 사용자 계정이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU1-13] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm uid_same.txt 2> /dev/null


echo " [SU1-14]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "################             SU1-14 불필요한 계정에 shell이 적절하게 부여되어 있는가?             ################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 로그인 불필요 사용자 Shell 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> passwd.txt
egrep -v "false$|nologin$" passwd.txt >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `cat /etc/passwd | wc -l` -ge 1 ]
then
	if [ `egrep -v "false$|nologin$" passwd.txt | wc -l` -ge 1 ]
	then
		echo "불필요한 계정에 shell이 부여되어 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-14] 취약 - SU1.14-불필요한 계정에 shell이 적절하게 부여되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "불필요한 계정에 shell이 부여되지않아 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-14] 양호 - SU1.14-불필요한 계정에 shell이 적절하게 부여되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
    echo "/etc/passwd 파일이 없습니다." >> $HOSTNAME.txt 2>&1
	echo "[SU1-14] N/A - SU1.14-불필요한 계정에 shell이 적절하게 부여되어 있는가?" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[SU1-14] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm passwd.txt 2> /dev/null


echo " [SU1-15]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "####################             SU1-15 Session Timeout 설정이 되어 있는가?             ###################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ --- sh, ksh, bash 사용 시 --- ]" >> $HOSTNAME.txt 2>&1
echo "[ /etc/profile 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/profile 2> /dev/null | egrep -i 'TMOUT|TIMEOUT' >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/profile ]
then
	if [ `egrep -i 'timeout|tmout' /etc/profile | grep -v "#" | sed -r 's/.*('timeout=[0-999]+'|'tmout=[0-999]+')(.*)/\1/i' | awk -F= '{print $2}'` -gt 600 2> /dev/null ]
	then
		echo "600초(10분)보다 크게 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> session_time.txt 2>&1
	else
		if [ `egrep -i 'timeout|tmout' /etc/profile | grep -v "#" | sed -r 's/.*('timeout=[0-999]+'|'tmout=[0-999]+')(.*)/\1/i' | awk -F= '{print $2}'` -z 2> /dev/null ]
		then
			echo "세션타임아웃 설정되어 있지 않으므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> session_time.txt 2>&1
		else
			echo "600초(10분) 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> session_time.txt 2>&1
		fi
	fi
else
	echo "/etc/profile 파일이 존재하지 않음"  >> $HOSTNAME.txt 2>&1
	echo "3" >> session_time.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ /.profile 확인 ]" >> $HOSTNAME.txt 2>&1
cat /.profile 2> /dev/null | egrep -i "TMOUT|TIMEOUT" >> $HOSTNAME.txt  2> /dev/null
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /.profile ]
then
	if [ `egrep -i 'timeout|tmout' /.profile | grep -v "#" | sed -r 's/.*('timeout=[0-999]+'|'tmout=[0-999]+')(.*)/\1/i' | awk -F= '{print $2}'` -gt 600 2> /dev/null ]
	then
		echo "600초(10분)보다 크게 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> session_time.txt 2>&1
	else
		if [ `egrep -i 'timeout|tmout' /.profile | grep -v "#" | sed -r 's/.*('timeout=[0-999]+'|'tmout=[0-999]+')(.*)/\1/i' | awk -F= '{print $2}'` -z 2> /dev/null ]
		then
			echo "세션타임아웃 설정되어 있지 않으므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> session_time.txt 2>&1
		else
			echo "600초(10분) 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> session_time.txt 2>&1
		fi
	fi
else
	echo "/.profile 파일이 존재하지 않음"  >> $HOSTNAME.txt 2>&1
	echo "3" >> session_time.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ ~/.bash_profile 확인 ]" >> $HOSTNAME.txt 2>&1
cat ~/.bash_profile 2> /dev/null | egrep -i "TMOUT|TIMEOUT" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f ~/.bash_profile ]
then
	if [ `egrep -i 'timeout|tmout' ~/.bash_profile | grep -v "#" | sed -r 's/.*('timeout=[0-999]+'|'tmout=[0-999]+')(.*)/\1/i' | awk -F= '{print $2}'` -gt 600 2> /dev/null ]
	then
		echo "600초(10분)보다 크게 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> session_time.txt 2>&1
	else
		if [ `egrep -i 'timeout|tmout' ~/.bash_profile | grep -v "#" | sed -r 's/.*('timeout=[0-999]+'|'tmout=[0-999]+')(.*)/\1/i' | awk -F= '{print $2}'` -z 2> /dev/null ]
		then
			echo "세션타임아웃 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> session_time.txt 2>&1
		else
			echo "600초(10분) 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> session_time.txt 2>&1
		fi
	fi
else
	echo "~/.bash_profile 파일이 존재하지 않음"  >> $HOSTNAME.txt 2>&1
	echo "3" >> session_time.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ --- csh, tch 사용하는 경우 --- ]" >> $HOSTNAME.txt 2>&1
echo "[ /etc/csh.login 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/csh.login 2> /dev/null | grep autologout >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/csh.login ]
then
	if [ `egrep -i 'autologout' /etc/csh.login | grep -v "#" | sed -r 's/.*(autologout=[0-999]+)(.*)/\1/i' | awk -F= '{print $2}'` -gt 10 2> /dev/null ]
	then
		echo "10분(600초)보다 크게 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> session_time.txt 2>&1
	else
		if [ `egrep -i 'autologout' /etc/csh.login | grep -v "#" | sed -r 's/.*(autologout=[0-999]+)(.*)/\1/i' | awk -F= '{print $2}'` -z 2> /dev/null ]
			then
				echo "세션타임아웃 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				echo "2" >> session_time.txt 2>&1
			else
				echo "10분(600초) 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
				echo "1" >> session_time.txt 2>&1
		fi
	fi
else
	echo "/etc/csh.login 파일이 존재하지 않음"  >> $HOSTNAME.txt 2>&1
	echo "3" >> session_time.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ /etc/csh.cshrc 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/csh.cshrc 2> /dev/null | grep autologout >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/csh.cshrc ]
then
	if [ `egrep -i 'autologout' /etc/csh.cshrc | grep -v "#" | sed -r 's/.*(autologout=[0-999]+)(.*)/\1/i' | awk -F= '{print $2}'` -gt 10 2> /dev/null ]
	then
		echo "10분(600초)보다 크게 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> session_time.txt 2>&1
	else
		if [ `egrep -i 'autologout' /etc/csh.cshrc | grep -v "#" | sed -r 's/.*(autologout=[0-999]+)(.*)/\1/i' | awk -F= '{print $2}'` -z 2> /dev/null ]
			then
				echo "세션타임아웃 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
				echo "2" >> session_time.txt 2>&1
			else
				echo "10분(600초) 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
				echo "1" >> session_time.txt 2>&1
		fi
	fi
else
	echo "/etc/csh.cshrc 파일이 존재하지 않음"  >> $HOSTNAME.txt 2>&1
	echo "3" >> session_time.txt 2>&1
fi

if [ -f session_time.txt ]
then
	if [ `sort -u session_time.txt | grep "1" | wc -l` -ge 1 ]
	then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-15] 양호 - SU1.15-Session Timeout 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
	elif [ `sort -u session_time.txt | grep "2" | wc -l` -ge 1 ]
	then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU1-15] 취약 - SU1.15-Session Timeout 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "[ CHECK ]: 설정값이 없거나 TMOUT(autologout)설정이 600초(10분)보다 크면 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-15] 수동 - SU1.15-Session Timeout 설정이 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU1-15] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm session_time.txt


echo "################### 2.File & Directory Management ###################"
echo "################### 2.파일 및 디렉터리 관리 ###################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " [SU2-01]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#############             SU2-01 root 계정의 PATH 환경변수에 \".\" 설정을 제거하였는가?             ##############"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ root 계정의 PATH 환경변수 확인 ]" >> $HOSTNAME.txt 2>&1
echo $PATH >> $HOSTNAME.txt 2>&1
echo $PATH | sed 's/\:/\n/g'>> path.txt
echo " " >> $HOSTNAME.txt 2>&1

if [ `egrep "^\.|^\.." path.txt | wc -l` -ge 1 ]
then
	echo "root 계정의 PATH 환경변수에 \".\"가 존재하여 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-14] 취약 - SU2.01-root 계정의 PATH 환경변수에 \".\" 설정을 제거하였는가?" >> $HOSTNAME.txt 2>&1
else
	echo "root 계정의 PATH 환경변수에 \".\"가 존재하지않아 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU1-14] 양호 - SU2.01-root 계정의 PATH 환경변수에 \".\" 설정을 제거하였는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-01] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm path.txt


echo " [SU2-02]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#############             SU2-02 소유자가 존재하지 않은 파일 및 디렉터리를 제거하였는가?             ##############"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 소유자가 존재하지 않은 디렉터리 확인 ]" >> $HOSTNAME.txt 2>&1
find /etc /tmp /bin /sbin -xdev -nouser -o -nogroup -exec ls -al {} \; 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `find /etc /tmp /bin /sbin -xdev -nouser -o -nogroup -exec ls -al {} \; 2> /dev/null` -z ]
then
	echo "소유자가 존재하지 않은 파일 및 디렉터리 존재하지않아 양호"  >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-02] 양호 - SU2.02-소유자가 존재하지 않은 파일 및 디렉터리를 제거하였는가?"  >> $HOSTNAME.txt 2>&1
else
	echo "소유자가 존재하지 않은 파일 및 디렉터리 존재하여 취약"  >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-02] 취약 - SU2.02-소유자가 존재하지 않은 파일 및 디렉터리를 제거하였는가?"  >> $HOSTNAME.txt 2>&1
fi
echo "[SU2-02] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-03]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "############             SU2-03 /etc/passwd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?             #########"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/passwd 확인 ]" >> $HOSTNAME.txt 2>&1

if [ -f /etc/passwd ]
then
	ls -alL /etc/passwd >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/passwd | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
	then
		echo "소유자가 root이고, 권한이 644 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-03] 양호 - SU2.03-/etc/passwd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
	else
		echo "소유자가 root가 아니거나, 권한이 644 이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-03] 취약 - SU2.03-/etc/passwd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
	fi
else
	echo "/etc/passwd 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-03] N/A - SU2.03-/etc/passwd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-03] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-04]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "###########             SU2-04 /etc/shadow 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?             ##########"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/shadow 확인 ]" >> $HOSTNAME.txt 2>&1

if [ -f /etc/shadow ]
then
	ls -alL /etc/shadow >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/shadow | grep "...-------.*root.*" | wc -l` -eq 1 ]
		then
			echo "소유자가 root이고, 권한이 600 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU2-04] 양호 - SU2.04-/etc/shadow 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
		else
			echo "소유자가 root가 아니거나, 권한이 600 이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU2-04] 취약 - SU2.04-/etc/shadow 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
	fi
else
	echo "/etc/shadow 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-04] N/A - SU2.04-/etc/shadow 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-04] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-05]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "###########             SU2-05 /etc/hosts 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?             ############"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/hosts 확인 ]" >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts ]
then
	ls -l /etc/hosts >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/hosts | grep "...-------.*root.*" | wc -l` -eq 1 ]
	then
		echo "소유자가 root이고, 권한이 600이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-05] 양호 - SU2.05-/etc/hosts 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "소유자가 root가 아니거나, 권한이 600이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-05] 취약 - SU2.05-/etc/hosts 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "/etc/hosts 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-05] N/A - SU2.05-/etc/hosts 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-05] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-06]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "########             SU2-06 /etc/(x)inetd.conf 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?             #########"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf ]
then
	echo "[ /etc/inetd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
	ls -alL /etc/inetd.conf >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/inetd.conf | grep "...-------.*root.*" | wc -l` -eq 1 ]
	then
		echo "소유자가 root이고, 권한이 600이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> inetd.txt 2>&1
	else
		echo "소유자가 root가 아니거나, 권한이 600이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> inetd.txt 2>&1
	fi
fi
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/xinetd.conf ]
then
	echo "[ /etc/xinetd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
	ls -alL /etc/xinetd.conf >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/xinetd.conf | grep "...-------.*root.*" | wc -l` -eq 1 ]
	then
		echo "소유자가 root이고, 권한이 600이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> inetd.txt 2>&1
	else
		echo "소유자가 root가 아니거나, 권한이 600이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> inetd.txt 2>&1
	fi
fi
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/xinetd.d/* ]
then
	echo "[ /etc/xinetd.d/* 확인 ]" >> $HOSTNAME.txt 2>&1
	ls -alL /etc/xinetd.d/* >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/xinetd.d/* | grep -v "...-------.*root.*" | wc -l` -eq 0 ]
	then
		echo "소유자가 root이고, 권한이 600이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> inetd.txt 2>&1
	else
		echo "소유자가 root가 아니거나, 권한이 600이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> inetd.txt 2>&1
	fi
fi
echo " " >> $HOSTNAME.txt 2>&1

if [ `sort -u inetd.txt | grep "2" | wc -l` -ge 1 ]
then
	echo "[SU2-06] 취약 - SU2.06-/etc/(x)inetd.conf 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
elif [ `sort -u inetd.txt | grep "1" | wc -l` -ge 1 ]
then
	echo "[SU2-06] 양호 - SU2.06-/etc/(x)inetd.conf 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[SU2-06] N/A - SU2.06-/etc/(x)inetd.d 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-06] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm inetd.txt


echo " [SU2-07]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#########             SU2-07 /etc/syslog.conf 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?             #########"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ -f /etc/syslog.conf ]
then
	echo "[ /etc/syslog.conf 확인 ]" >> $HOSTNAME.txt 2>&1
	ls -lL /etc/syslog.conf  >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/syslog.conf | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
	then
		echo "1" >> syslog.txt 2>&1
	else
		echo "2" >> syslog.txt 2>&1
	fi
elif [ -f /etc/rsyslog.conf ] ; then
	echo "[ /etc/rsyslog.conf 확인 ]" >> $HOSTNAME.txt 2>&1
	ls -lL /etc/rsyslog.conf  >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/rsyslog.conf | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
	then
		echo "1" >> syslog.txt 2>&1
	else
		echo "2" >> syslog.txt 2>&1
	fi
else
	echo "3" >> syslog.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

if [ `sort -u syslog.txt | grep "1" | wc -l` -eq 1 ]
then
	echo "소유자가 root이고, 권한이 644이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-07] 양호 - SU2.07-/etc/syslog.conf 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
elif [ `sort -u syslog.txt | grep "2" | wc -l` -eq 1 ]
then
	echo "소유자가 root가 아니거나, 권한이 644이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-07] 취약 - SU2.07-/etc/syslog.conf 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "/etc/(r)syslog.conf가 존재하지 않는다면 미설치된것으로 N/A"    >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-07] N/A - SU2.07-/etc/syslog.conf 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-07] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm syslog.txt


echo " [SU2-08]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "##########             SU2-08 /etc/services 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?             ##########"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
if [ -f /etc/services ]
then
	echo "[ /etc/services 확인 ]" >> $HOSTNAME.txt 2>&1
	ls -lL /etc/services >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/services | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
	then
		echo "소유자가 root이고, 권한이 644이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-08] 양호 - SU2.08-/etc/services 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "소유자가 root가 아니거나, 권한이 644이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-08] 취약 - SU2.08-/etc/services 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "/etc/services 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-08] N/A - SU2.08-/etc/services 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-08] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-09]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "###########           SU2-09 주요파일에 SUID, SGID, Sticky bit 설정이 적절하게 되어 있는가?             ##########"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /usr 확인 ]" >> $HOSTNAME.txt 2>&1
find /usr -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;  2> /dev/null >> SUID1.txt
cat SUID1.txt | grep 'dump$\|lpd-lpd\|restore$\|lpr$\|lpc$\|lpr-lpd\|lpc-lpd\|lprm$\|traceroute$\|lpq$\|lprm-lpd\|newgrp$\|unix_chkpwd$\|at$' >> $HOSTNAME.txt 2>&1
cat SUID1.txt | grep 'dump$\|lpd-lpd\|restore$\|lpr$\|lpc$\|lpr-lpd\|lpc-lpd\|lprm$\|traceroute$\|lpq$\|lprm-lpd\|newgrp$\|unix_chkpwd$\|at$' >> SUID.txt
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /bin 확인 ]" >> $HOSTNAME.txt 2>&1
find /bin -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;  2> /dev/null >> SUID2.txt
cat SUID2.txt | grep 'dump$\|lpd-lpd\|restore$\|lpr$\|lpc$\|lpr-lpd\|lpc-lpd\|lprm$\|traceroute$\|lpq$\|lprm-lpd\|newgrp$\|unix_chkpwd$\|at$' >> $HOSTNAME.txt 2>&1
cat SUID2.txt | grep 'dump$\|lpd-lpd\|restore$\|lpr$\|lpc$\|lpr-lpd\|lpc-lpd\|lprm$\|traceroute$\|lpq$\|lprm-lpd\|newgrp$\|unix_chkpwd$\|at$' >> SUID.txt
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /sbin 확인 ]" >> $HOSTNAME.txt 2>&1
find /sbin -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \; 2> /dev/null >> SUID3.txt
cat SUID3.txt | grep 'dump$\|lpd-lpd\|restore$\|lpr$\|lpc$\|lpr-lpd\|lpc-lpd\|lprm$\|traceroute$\|lpq$\|lprm-lpd\|newgrp$\|unix_chkpwd$\|at$' >> $HOSTNAME.txt 2>&1
cat SUID3.txt | grep 'dump$\|lpd-lpd\|restore$\|lpr$\|lpc$\|lpr-lpd\|lpc-lpd\|lprm$\|traceroute$\|lpq$\|lprm-lpd\|newgrp$\|unix_chkpwd$\|at$' >> SUID.txt
echo " " >> $HOSTNAME.txt 2>&1

if [ `cat SUID.txt | wc -l` -gt 0 ]
then
	echo "주요파일에 SUID, SGID, Sticky bit가 존재하여 취약"  >> $HOSTNAME.txt 2>&1
	echo " "  >> $HOSTNAME.txt 2>&1
	echo "[SU2-09] 취약 - SU2.09-주요파일에 SUID, SGID, Sticky bit 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "주요파일에 SUID, SGID, Sticky bit가 존재하지않아 양호"  >> $HOSTNAME.txt 2>&1
	echo " "  >> $HOSTNAME.txt 2>&1
	echo "[SU2-09] 양호 - SU2.09-주요파일에 SUID, SGID, Sticky bit 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-09] End" >> $HOSTNAME.txt 2>&1
echo " "  >> $HOSTNAME.txt 2>&1
echo " "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm SUID*.txt


echo " [SU2-10]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#########           SU2-10 홈 디렉터리 환경변수 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?             ########"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 환경변수 파일 확인 ]" >> $HOSTNAME.txt 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
 do
    FILE=/$file
    if [ -f $FILE ]
    then
        ls -al $FILE  >> $HOSTNAME.txt 2>&1
    fi
 done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
    then
        ls -al $FILE  >> $HOSTNAME.txt 2>&1
    fi
  done
done

for file in $FILES
do
    if [ -f /$file ]
    then
        if [ `ls -alL /$file |  awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
        then
            echo "1"  >> home2.txt
        else
            echo "2"  >> home2.txt
        fi
    else
        echo "1"  >> home2.txt
    fi
done

for dir in $HOMEDIRS
do
    for file in $FILES
    do
        if [ -f $dir/$file ]
        then
            if [ `ls -al $dir/$file | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
            then
				echo "1"  >> home2.txt
            else
                echo "2"  >> home2.txt
			fi
        else
            echo "1"  >> home2.txt
        fi
    done
done
echo " " >> $HOSTNAME.txt 2>&1

if [ `cat home2.txt | grep "2" | wc -l` -eq 0 ]
then
	echo "홈 디렉터리 환경변수 파일의 소유자 및 권한 설정이 올바르게 설정되어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-10] 양호 - SU2.10-홈 디렉터리 환경변수 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
else
	echo "홈 디렉터리 환경변수 파일의 소유자 및 권한 설정이 올바르게 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-10] 취약 - SU2.10-홈 디렉터리 환경변수 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?"  >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-10] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm home2.txt
unset HOMEDIRS
unset FILES


echo " [SU2-11]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "####################           SU2-11 world writable 파일을 제거되어 있는가?             ####################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ world writable 파일 확인 ]" >> $HOSTNAME.txt 2>&1

if [ `find / -xdev -perm -2 -ls | grep -v 'lrwxrwxrwx' | grep -v 'srwxrwxrwx' | grep -v 'srw-rw-rw-' | tail -1 | wc -l` -eq 0 ]
then
	echo "World Writable 파일이 존재하지 않으므로 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-11] 양호 - SU2.11-world writable 파일을 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo " ">> $HOSTNAME-SystemInformation.txt 2>&1
	echo "==================================================================="  >> $HOSTNAME-SystemInformation.txt 2>&1
	echo "============== SU2-11 world writable 파일을 제거되어 있는가? =============="  >> $HOSTNAME-SystemInformation.txt 2>&1
	echo "==================================================================="  >> $HOSTNAME-SystemInformation.txt 2>&1
	echo " ">> $HOSTNAME-SystemInformation.txt 2>&1

	find / -xdev -perm -2 -ls | grep -v 'lrwxrwxrwx' | grep -v 'srwxrwxrwx' | grep -v 'srw-rw-rw-' | tail -15000 >> $HOSTNAME-SystemInformation.txt 2>&1
	find / -xdev -perm -2 -ls | grep -v 'lrwxrwxrwx' | grep -v 'srwxrwxrwx' | grep -v 'srw-rw-rw-' | tail -15 >> $HOSTNAME.txt 2>&1
	echo " ">> $HOSTNAME-SystemInformation.txt 2>&1
	echo "* 해당 결과 파일은 $HOSTNAME-SystemInformation.txt 파일 참고" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-11] 수동 - SU2.11-world writable 파일을 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-11] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-12]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "##############           SU2-12 /dev에 존재하지 않은 device 파일이 제거되어 있는가?             ################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ device 파일 확인 ]" >> $HOSTNAME.txt 2>&1
find /dev -type f -exec ls -l {} \; >> $HOSTNAME.txt 2>&1

if [ `find /dev -type f -exec ls -l {} \; | wc -l` -eq 0 ]
then
	echo "device 파일이 존재하지 않으므로 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-12] 양호 - SU2.12-/dev에 존재하지 않은 device 파일이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[ ---------------------------------------------------------------------- ]"	>> $HOSTNAME.txt 2>&1
	echo "  왼쪽숫자는 Major Number 이며 우축숫자는 Minor Number이다." 								>> $HOSTNAME.txt 2>&1
	echo "  주요정보통신기반시설 가이드라인에서는 Major, Minor Number를 가지고 있지 않는 파일은"					>> $HOSTNAME.txt 2>&1
	echo "  잘못된 파일 혹은 사용하지 않는 불필요한 파일일 가능성이 높으므로 확인 후 제거할것을 권고한다." 				>> $HOSTNAME.txt 2>&1
	echo "  ex) -rw-r--r-- 1 root root 80 Feb  9 20:24 /dev/.udev/db/block:loop1"		>> $HOSTNAME.txt 2>&1
	echo "  날짜 feb 월을 기준으로 왼쪽에 있는숫자가 Number이며 하나만 표시되면 Major Number이다."    			>> $HOSTNAME.txt 2>&1
	echo "[ ---------------------------------------------------------------------- ]"	>> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-12] 수동 - SU2.12-/dev에 존재하지 않은 device 파일이 제거되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-12] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-13]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "############           SU2-13 \$HOME/.rhosts 및 hosts.equiv 사용을 제한하고 있는가?            ##############"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ hosts.equiv 확인 ]" >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts.equiv ]
then
	cat /etc/hosts.equiv >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	ls -l /etc/hosts.equiv >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/hosts.equiv | grep ".r.-------.*root.*" | wc -l` -eq 1 ]
			then
				echo "/etc/hosts.equiv가 600이하로 설정되어 양호" >> $HOSTNAME.txt 2>&1
			else
				echo "/etc/hosts.equiv가 600이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		fi
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "/etc/hosts.equiv 파일이 존재하지 않으므로 양호" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ .rhosts 확인 ]" >> $HOSTNAME.txt 2>&1

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`

for dir in $HOMEDIRS
do
	if [ -f $dir/.rhosts ]
	then
		ls -la $dir/.rhosts >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		cat $dir/.rhosts >> $HOSTNAME.txt
	else
		echo "$dir/.rhosts 파일이 없습니다." >> $HOSTNAME.txt 2>&1
	fi
done

echo " " >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 1. rsh, rlogin, rexec 등을 사용하지 않으면 양호" >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 2. 부득이한 경우 권한을 600으로 설정 및 특정 호스트만 사용가능하도록 설정하면 양호" >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 3. 해당 파일이 존재하지 않아도 양호 처리" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[SU2-13] 수동 - SU2.13-\$HOME/.rhosts 및 hosts.equiv 사용을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU2-13] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-14]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#############           SU2-14 hosts.lpd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?           ############"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/hosts.lpd 확인 ]" >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts.lpd ]
then
	ls -al /etc/hosts.lpd >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `ls -alL /etc/hosts.lpd | grep ".r.-------.*.*" | wc -l` -eq 1 ]
	then
		echo "소유자가 root이고, 권한이  600 이하로 설정되어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-14] 양호 - SU2.14-hosts.lpd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "소유자가 root이고, 권한이  600 이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU2-14] 취약 - SU2.14-hosts.lpd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "/etc/hosts.lpd 파일이 없음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-14] 양호 - SU2.14-hosts.lpd 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-14] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-15]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "###################           SU2-15 불필요한 NIS 서비스를 비활성화하고 있는가?           ###################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ NIS, NIS+ 서비스 확인 ]" >> $HOSTNAME.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
    echo " " >> $HOSTNAME.txt 2>&1
    echo "NIS, NIS+ 서비스가 비활성화 중이므로 양호" >> $HOSTNAME.txt 2>&1
    echo " " >> $HOSTNAME.txt 2>&1
    echo "[SU2-15] 양호 - SU2.15-불필요한 NIS 서비스를 비활성화하고 있는가?" >> $HOSTNAME.txt 2>&1
else
    ps -ef | egrep $SERVICE | grep -v "grep" >> $HOSTNAME.txt 2>&1
    echo " " >> $HOSTNAME.txt 2>&1
    echo "[SU2-15] 수동 - SU2.15-불필요한 NIS 서비스를 비활성화하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-15] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU2-16]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "############           SU2-16 umask 설정이 임의의 사용자에게 쓰기권한이 제한하고 있는가?           #############"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ umask 설정 확인 ]"  >> $HOSTNAME.txt 2>&1
umask  >> $HOSTNAME.txt 2>&1
UMASK_C=`umask`
echo " " >> $HOSTNAME.txt 2>&1

if [ $UMASK_C -le 022 ]
then
	echo "UMASK 값이 022 이상으로 설정되어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-16] 양호 - SU2.16-umask 설정이 임의의 사용자에게 쓰기권한이 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "UMASK 값이 022 이상으로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-16] 취약 - SU2.16-umask 설정이 임의의 사용자에게 쓰기권한이 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-16] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset UMASK_C


echo " [SU2-17]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "#############           SU2-17 사용자 홈 디렉터리 소유자 및 권한 설정이 적절하게 되어 있는가?           ############"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ UID 500이상 사용자의 홈 디렉터리 확인 ]"     >> $HOSTNAME.txt 2>&1
HOMEDIRS=`cat /etc/passwd | sort -u | awk -F":" 'length($6) > 0 && $3 > 500 || $3 == 500 {print $6}' | grep -wv "\/"`

for dir in $HOMEDIRS
do
    ls -dal $dir 2> /dev/null | grep '\d.........' >> $HOSTNAME.txt 2>&1
done
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/passwd 파일 내 UID 500이상 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | sort -u | awk -F":" 'length($6) > 0 && $3 > 500 || $3 == 500 {print}' | grep -wv "\/" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ ------------------------------------------------------------ ]"  >> $HOSTNAME.txt 2>&1
echo "  UID가 500을 넘어가는 계정을 중점 확인[그 이하는 시스템 계정]"     >> $HOSTNAME.txt 2>&1
echo "  홈디렉터리가 존재하는 계정 중 소유자, 퍼미션확인 그 외 사용자가 쓰기 권한을 가지면 안된다."    >> $HOSTNAME.txt 2>&1
echo "[ ------------------------------------------------------------ ]"  >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "[SU2-17] 수동 - SU2.17-사용자 홈 디렉터리 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU2-17] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset HOMEDIRS


echo " [SU2-18]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "###############           SU2-18 홈 디렉터리가 존재하지 않는 계정을 점검하고 있는가?           #################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
for U29 in `cat /etc/passwd | awk -F: 'length($6) > 0 && $3 > 500 || $3 == 500 { print $1 }'`
do
	if [ -d `cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'` ]
	then
		TMP_HOMEDIR=`cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'`
		TMP_HOMEDIR2=`cat /etc/passwd | grep $U29 | awk -F: '{ print $3 }'`
		echo "점검 ID : $U29" >> $HOSTNAME.txt 2>&1
		echo "홈 디렉터리 : $TMP_HOMEDIR" >> $HOSTNAME.txt 2>&1
		echo "계정의 UID : $TMP_HOMEDIR2" >> $HOSTNAME.txt 2>&1
		echo "/etc/passwd에 설정된 디렉터리 $TMP_HOMEDIR 존재" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "1" >> home_dir.txt 2>&1
	else
		TMP_HOMEDIR=`cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'`
		echo "점검 ID : $U29" >> $HOSTNAME.txt 2>&1
		echo "홈 디렉터리 : $TMP_HOMEDIR" >> $HOSTNAME.txt 2>&1
		echo "/etc/passwd에 설정된 디렉터리 $TMP_HOMEDIR 없음" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "2" >> home_dir.txt 2>&1
	fi
done

if [ `sort -u home_dir.txt | grep "2" | wc -l` -eq 1 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-18] 취약 - SU2.18-홈 디렉터리가 존재하지 않는 계정을 점검하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU2-18] 양호 - SU2.18-홈 디렉터리가 존재하지 않는 계정을 점검하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU2-18] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm home_dir.txt


echo " [SU2-19]  Checking..."
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo "####################           SU2-19 불필요한 숨겨진 파일을 제거하고 있는가?           #####################"  >> $HOSTNAME.txt 2>&1
echo "####################################################################################### "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
find / -xdev -name ".*" -ls | tail -50  >> $HOSTNAME.txt 2>&1

echo "==================================================================="  >> $HOSTNAME-SystemInformation.txt 2>&1
echo "=============SU2-19 불필요한 숨겨진 파일을 제거하고 있는가? ================="  >> $HOSTNAME-SystemInformation.txt 2>&1
echo "==================================================================="  >> $HOSTNAME-SystemInformation.txt 2>&1
find / -xdev -name "..*" -ls >> $HOSTNAME-SystemInformation.txt 2>&1
find / -xdev -name ".*" -ls  >> $HOSTNAME-SystemInformation.txt 2>&1
echo " ">> $HOSTNAME-SystemInformation.txt 2>&1
echo " ">> $HOSTNAME-SystemInformation.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 1. 의심스러운 숨겨진 파일 및 디렉터리가 없을 시 양호" >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 2. 관리자 인터뷰 후 양호, 취약 판단 불가할시 N/A 처리" >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 3. 해당 결과는 최대 50개의 결과만 출력"  >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 4. 모든 결과는 $HOSTNAME-SystemInformation.txt 참고"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[SU2-19] 수동 - SU2.19-불필요한 숨겨진 파일을 제거하고 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU2-19] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "################### 3. Service Management ###################"
echo "################### 3. 서비스 관리 ###################" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " [SU3-01]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo  "########################      SU3-01 접속 IP 및 포트를 제한하고 있는가?    ##########################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ TCP Wrapper 확인 ]" >> $HOSTNAME.txt 2>&1
rpm -qa 2> /dev/null | grep tcpd >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[ /etc/hosts.allow 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/hosts.allow 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[ /etc/hosts.deny 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/hosts.deny 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

file=`which tcpd`

if [ -f $file ]
then
	if [ -f /etc/hosts.deny 2> /dev/null ]
	then
		if [ `cat /etc/hosts.deny | grep "ALL:ALL" | wc -l` -eq 0 ]
		then
			echo "별도의 서버 접근제어 솔루션 운영하는지 인터뷰 필요" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-1] 수동 - SU3.01-접속 IP 및 포트를 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "[SU3-1] 양호 - SU3.01-접속 IP 및 포트를 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	fi
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "별도의 서버 접근제어 솔루션 운영하는지 인터뷰 필요" >> $HOSTNAME.txt 2>&1
	echo "[ CHECK]: 1. /etc/hosts.deny에서 all deny 설정 확인"  >> $HOSTNAME.txt 2>&1
	echo "[ CHECK]: 2. /etc/hosts.allow에서 접근 가능 서비스 및 IP가 설정 확인" >> $HOSTNAME.txt 2>&1
	echo "[ CHECK]: 3. 위 2가지 설정이 적용되어 있는 경우 양호" >> $HOSTNAME.txt 2>&1
	echo "[ CHECK]: 4. 별도의 서버 접근제어 솔루션 운영 시 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-01] 수동 - SU3.01-접속 IP 및 포트를 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-01] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-02]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "####################     SU3-02 불필요한 Finger 서비스를 비활성화 하고 있는가?    ######################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/inetd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf 2> /dev/null ]
then
	cat /etc/inetd.conf | grep "^#" | grep "finger" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ cat /etc/inetd.conf | grep "^#" | grep "finger" ]
	then
		echo "/etc/inetd.conf 파일에 Finger 서비스 설정이 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> finger.txt 2>&1
	elif [ cat /etc/inetd.conf | grep "finger" ] ; then
		echo "/etc/inetd.conf 파일에 Finger 서비스 설정이 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> finger.txt 2>&1
	else
		echo "/etc/inetd.conf 파일에 Finger 서비스 설정이 존재하지 않음" >> $HOSTNAME.txt 2>&1
		echo "3" >> finger.txt 2>&1
	fi
else
    echo "/etc/inetd.conf 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo "1" >> finger.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/xinetd.d/finger 확인 ]" >> $HOSTNAME.txt 2>&1
if [ `ls -alL /etc/xinetd.d 2> /dev/null | egrep finger | wc -l` -gt 0 ]
then
	cat /etc/xinetd.d/finger | grep -i "disable" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `cat /etc/xinetd.d/finger | grep -i "disable" | awk -F= '{print $2}' | grep -i "yes" | wc -l` -eq 1 ]
	then
		echo "/etc/xinetd.d/finger 파일에 Finger 서비스가 disable = yes로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> finger.txt 2>&1
	else
		echo "/etc/xinetd.d/finger 파일에 Finger 서비스가 disable = no로 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> finger.txt 2>&1
	fi
else
    echo "/etc/xinetd.d/에 finger파일이 없습니다" >> $HOSTNAME.txt 2>&1
	echo "1" >> finger.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ Finger 서비스(79번 포트) 확인] ]" >> $HOSTNAME.txt 2>&1
netstat -na | grep tcp | grep ":79 " | grep LISTEN >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -na | grep ":79 " | grep LISTEN | grep tcp | wc -l` -eq 0 ]
then
	echo "Finger 서비스가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo "1" >> finger.txt 2>&1
else
	echo "Finger 서비스가 활성화되어있어 취약" >> $HOSTNAME.txt 2>&1
	echo "2" >> finger.txt 2>&1
fi

if [ `sort -u finger.txt | grep "2" | wc -l` -ge 1 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-02] 취약 - SU3.02-불필요한 Finger 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-02] 양호 - SU3.02-불필요한 Finger 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-02] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm finger.txt


echo " [SU3-03]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "###################     SU3-03 불필요한 Anonymous FTP를 비활성화 하고 있는가?    ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 21번 포트 확인 ]" >> $HOSTNAME.txt 2>&1
if [ `netstat -na | grep tcp | grep ":21 " | grep LISTEN | wc -l` -ne 0 ]
then
	netstat -na | grep tcp | grep 21 | grep LISTEN >> $HOSTNAME.txt 2>&1
else
	echo "21번 포트가 오픈되지않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 일반 FTP 및 ProFTP 확인 (ftp 계정유무 확인) ]" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | grep ftp >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ vsFTP 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/vsftpd.conf 2> /dev/null | egrep -i anonymous_enable >> $HOSTNAME.txt 2>&1
cat /etc/vsftpd/vsftpd.conf 2> /dev/null | egrep -i anonymous_enable >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -na | grep tcp | grep ":21 " | grep LISTEN | wc -l` -ne 0 ]
then
	if [ -f /etc/vsftpd.conf 2> /dev/null ]
	then
        if [ `cat /etc/vsftpd.conf 2> /dev/null | egrep -i anonymous_enable | awk -F= '{ print $2 }' | egrep -i "no" | wc -l` -eq 1 ]
		then
			echo "Anonymous FTP 접속이 차단되어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-03] 양호 - SU3.03-불필요한 Anonymous FTP를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "Anonymous FTP 접속이 차단되지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-03] 취약 - SU3.03-불필요한 Anonymous FTP를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	elif [ -f /etc/vsftpd/vsftpd.conf 2> /dev/null ]
	then
		if [ `cat /etc/vsftpd/vsftpd.conf | egrep -i anonymous_enable | awk -F= '{ print $2 }' | egrep -i "no" | wc -l` -eq 1 ]
		then
			echo "Anonymous FTP 접속이 차단되어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-03] 양호 - SU3.03-불필요한 Anonymous FTP를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "Anonymous FTP 접속이 차단되지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-03] 취약 - SU3.03-불필요한 Anonymous FTP를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	else
		if [ `cat /etc/passwd | egrep "ftp|anonymous" | wc -l` -eq 0 ]
		then
			echo "Anonymous FTP 접속이 차단되어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-03] 양호 - SU3.03-불필요한 Anonymous FTP를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "Anonymous FTP 접속이 차단되지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-03] 취약 - SU3.03-불필요한 Anonymous FTP를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	fi
else
	echo "TCP 21번 포트가 오픈되지 않았을 경우 N/A" >> $HOSTNAME.txt 2>&1
    echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-03] N/A - SU3.03-불필요한 Anonymous FTP를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-03] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " [SU3-04]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "########################     SU3-04 r 계열 서비스를 비활성화 하고 있는가?    #########################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/xinetd.d 파일의 rsh, rlogin, rexec 확인 ]" >> $HOSTNAME.txt 2>&1
SERVICE_INETD="rsh|rlogin|rexec"

if [ `ls -alL /etc/xinetd.d 2> /dev/null | egrep $SERVICE_INETD | wc -l` -gt 0 ]
then
    for rser in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
    do
	if [ `cat /etc/xinetd.d/$rser | grep -i "disable" | awk -F= '{print $2}' | grep -i "yes" | wc -l` -eq 1 ]
	then
		cat /etc/xinetd.d/$rser | grep -i "disable" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "/etc/xinetd.d/$rser 파일에 disable = yes로 설정되어 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> rservice.txt 2>&1
	else
		cat /etc/xinetd.d/$rser | grep -i "disable" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "/etc/xinetd.d/$rser 파일에 disable = no로 설정되어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> rservice.txt 2>&1
	fi
    done
else
	if [ -d /etc/xinetd.d 2> /dev/null ]
	then
		echo "/etc/xinetd.d 디렉터리에 r계열 서비스 없음" >> $HOSTNAME.txt 2>&1
		echo "1" >> rservice.txt 2>&1
	else
		echo "/etc/xinetd.d 디렉터리가 존재하지 않음" >> $HOSTNAME.txt 2>&1
		echo "3" >> rservice.txt 2>&1
	fi
fi

SERVICE_INETD2="shell|login|exec"
echo " " >> $HOSTNAME.txt 2>&1
echo "[ /etc/inetd.conf 파일의 rsh, rlogin, rexec 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf 2> /dev/null ]
then
    cat /etc/inetd.conf | grep -v '^#' | egrep $SERVICE_INETD2 | egrep -v "grep|klogin|kshell|kexec" >> $HOSTNAME.txt 2>&1
else
    echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $HOSTNAME.txt 2>&1
	echo "3" >> rservice.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ rexec(512), rlogin(513), rsh(514) 포트 오픈 확인 ]" >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep :512 | grep LISTEN >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep :513 | grep LISTEN >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep :514 | grep LISTEN >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -na | egrep ":512 |:513 |:514" | grep LISTEN | grep tcp | wc -l` -eq 0 ]
then
	echo "r계열 서비스 포트가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo "1" >> rservice.txt 2>&1
else
	echo "r계열 서비스 포트가 활성화되어있어 취약" >> $HOSTNAME.txt 2>&1
	echo "2" >> rservice.txt 2>&1
fi

if [ `sort -u rservice.txt | grep "2" | wc -l` -ge 1 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-04] 취약 - SU3.04-r 계열 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-04] 양호 - SU3.04-r 계열 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-04] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset SERVICE_INETD
unset SERVICE_INETD2
rm rservice.txt


echo " [SU3-05]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#################     SU3-05 cron 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?    ##################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
ls -al /etc/cron.allow >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
ls -al /etc/cron.deny >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

permitCheck="...-.-----.*root.*"
etcPermitCheck="........wx.*root.*|..ws.....x.*root.*|.....ws..x.*root.*"

if [ -f /etc/cron.allow 2> /dev/null -a -f /etc/cron.deny 2> /dev/null ]
then
	if [ `ls -alL /etc/cron.allow | egrep $permitCheck | wc -l` -ne 0 -a `ls -alL /etc/cron.deny | egrep $permitCheck | wc -l` -ne 0 ]
	then
		echo "/etc/cron.allow,deny의 권한이 640이하로 설정되어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-05] 양호 - SU3.05-cron 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	elif [ `ls -alL /etc/cron.allow | egrep $permitCheck | wc -l` -ne 0 -o `ls -alL /etc/cron.deny | egrep $permitCheck | wc -l` -ne 0 ] ; then
		echo "/etc/cron.allow,deny 중 하나의 권한이 640이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-05] 취약 - SU3.05-cron 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/cron.allow,deny의 권한이 640이하로 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-05] 취약 - SU3.05-cron 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	if [ `ls -alL / | grep -w "etc" | egrep $etcPermitCheck | wc -l` -eq 0 ]
	then
		echo "cron.allow 또는 deny 파일이 없지만, /etc를 Other 권한으로 해당 파일 생성 및 수정이 불가하여 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[ /etc 권한 확인 ]" >> $HOSTNAME.txt 2>&1
		ls -alL / | grep etc >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-05] 양호 - SU3.05-cron 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "cron.allow 또는 deny 파일이 없고, /etc를 Other 권한으로 해당 파일 생성 및 수정이 가능하여 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[ /etc 권한 확인 ]" >> $HOSTNAME.txt 2>&1
		ls -alL / | grep etc >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-05] 취약 - SU3.05-cron 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU3-05] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset permitCheck
unset etcPermitCheck


echo " [SU3-06]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "####################     SU3-06 DoS 공격에 취약한 서비스를 비활성화 하고 있는가?    ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/xinetd.d 확인 ]" >> $HOSTNAME.txt 2>&1
DOS_INETD="echo|discard|daytime|chargen"

if [ `ls -alL /etc/xinetd.d 2> /dev/null | egrep $DOS_INETD | wc -l` -gt 0 ]
then
    for dosser in `ls -alL /etc/xinetd.d | egrep $DOS_INETD | grep -v "ssf" | awk '{print $9}'`
    do
	if [ `cat /etc/xinetd.d/$dosser | grep -i "disable" | awk -F= '{print $2}' | grep -i "yes" | wc -l` -ge 1 ]
	then
		echo "/etc/xinetd.d/$dosser 파일에 disable = yes로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		cat /etc/xinetd.d/$dosser | grep -i "disable" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "1" >> DoSservice.txt 2>&1
	else
		echo "/etc/xinetd.d/$dosser 파일에 disable = no로 설정되어있어 취약 " >> $HOSTNAME.txt 2>&1
		cat /etc/xinetd.d/$dosser | grep -i "disable" >> $HOSTNAME.txt 2>&1
		echo "2" >> DoSservice.txt 2>&1
	fi
    done
else
	if [ -d /etc/xinetd.d 2> /dev/null ]
	then
		echo "/etc/xinetd.d 디렉터리에 DOS공격에 취약한 서비스가 없음" >> $HOSTNAME.txt 2>&1
		echo "1" >> DoSservice.txt 2>&1
	else
		echo "/etc/xinetd.d 디렉터리가 존재하지 않음" >> $HOSTNAME.txt 2>&1
		echo "3" >> DoSservice.txt 2>&1
	fi
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "[ /etc/inetd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf 2> /dev/null ]
then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $DOS_INETD >> $HOSTNAME.txt 2>&1
else
    echo "/etc/inetd.conf 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ echo(7), discard(9), daytime(13), chargen(19) 포트 오픈 확인 ]" >> $HOSTNAME.txt 2>&1
netstat -na | grep ":7 " | grep LISTEN | grep tcp >> $HOSTNAME.txt 2>&1
netstat -na | grep ":9 " | grep LISTEN | grep tcp >> $HOSTNAME.txt 2>&1
netstat -na | grep ":13 " | grep LISTEN | grep tcp >> $HOSTNAME.txt 2>&1
netstat -na | grep ":19 " | grep LISTEN | grep tcp >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -na | egrep ":7 |:9 |:13 |:19 " | grep LISTEN | grep tcp | wc -l` -eq 0 ]
then
	echo "DoS공격에 취약한 서비스 포트가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo "1" >> DoSservice.txt 2>&1
else
	echo "DoS공격에 취약한 서비스 포트가 활성화있어 취약" >> $HOSTNAME.txt 2>&1
	echo "2" >> DoSservice.txt 2>&1
fi

if [ `sort -u DoSservice.txt | grep "2" | wc -l` -ge 1 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-06] 취약 - SU3.06-DoS 공격에 취약한 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-06] 양호 - SU3.06-DoS 공격에 취약한 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-06] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset DOS_INETD
rm DoSservice.txt


echo " [SU3-07]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "######################     SU3-07 불필요한 NFS 서비스가 비활성화 되어 있는가?    #####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 프로세스 구동 상태 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep mountd | egrep -v grep >> $HOSTNAME.txt 2>&1
ps -ef | grep nfs | egrep -v grep >> $HOSTNAME.txt 2>&1
ps -ef | grep statd | egrep -v grep >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ nfs(2049) 포트 오픈 확인 ]" >> $HOSTNAME.txt 2>&1
netstat -na | grep :2049 | grep LISTEN >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ rpcinfo 확인 ]" >> $HOSTNAME.txt 2>&1
rpcinfo -p localhost 2> /dev/null >> $HOSTNAME.txt 2>&1
echo "# 우분투는 해당 항목 확인 제외" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -na | grep ":2049 " | grep LISTEN | wc -l` -eq 0 ]
then
	echo "NFS 서비스가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-07] 양호 - SU3.07-불필요한 NFS 서비스가 비활성화 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	if [ `netstat -al | grep nfs | grep LISTEN | wc -l` -eq 0 ]
	then
		echo "NFS 서비스가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-07] 양호 - SU3.07-불필요한 NFS 서비스가 비활성화 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "NFS 서비스가 활성화되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-07] 취약 - SU3.07-불필요한 NFS 서비스가 비활성화 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU3-07] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-08]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "###################     SU3-08 NFS 서비스의 접근통제 설정이 적절하게 되어 있는가?    ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
if [ `ps -ef | egrep "nfs" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
then
	if [ -f /etc/exports 2> /dev/null ]
    then
		echo "[ /etc/exports 설정 확인 ]" >> $HOSTNAME.txt 2>&1
		cat /etc/exports >> $HOSTNAME.txt 2>&1
		if [ `cat /etc/exports | grep  "*" | wc -l` -eq 0 ]
		then
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-08] 양호 - SU3.08-NFS 서비스의 접근통제 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-08] 취약 - SU3.08-NFS 서비스의 접근통제 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		fi
    else
		echo "/etc/exports 파일 없음"  >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-08] 취약 - SU3.08-NFS 서비스의 접근통제 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	echo "NFS 서비스를 사용하지 않음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-08] N/A - SU3.08-NFS 서비스의 접근통제 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-08] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-09]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#################     SU3-09 불필요한 automountd 서비스를 비활성화 하고 있는가?    ####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ automountd 확인 ]"   >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep automountd | egrep -v "grep|rpc|statdaemon|emi" | wc -l` -eq 0 ]
then
    echo "automountd 서비스 검색결과 없어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-09] 양호 - SU3.09-불필요한 automountd 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
    ps -ef | grep automountd | egrep -v "grep|rpc|statdaemon|emi" >> $HOSTNAME.txt 2>&1
    echo "automountd 서비스가 존재하여 취약" >> $HOSTNAME.txt 2>&1
    echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-09] 취약 - SU3.09-불필요한 automountd 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-09] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-10]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#####################     SU3-10 불필요한 RPC 서비스를 비활성화 하고 있는가?    ######################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/xinetd.d 확인 ]" >> $HOSTNAME.txt 2>&1
SERVICE_INETD="rpc.sprayd|rpc.rstatd|rpc.rexd|rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd|rpc.rwalld|rpc.rusersd"

if [ `ls -alL /etc/xinetd.d 2> /dev/null | egrep $SERVICE_INETD | wc -l` -gt 0 ]
then
    for rpcser in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
    do
	if [ `cat /etc/xinetd.d/$rpcser | grep -i "disable" | awk -F= '{print $2}' | grep -i "yes" | wc -l` -eq 1 ]
	then
		cat /etc/xinetd.d/$rpcser | grep -i "disable" >> $HOSTNAME.txt 2>&1
		echo "/etc/xinetd.d/$rpcser 파일에 disable = yes로 설정되어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "1" >> RPCservice.txt 2>&1
	else
		cat /etc/xinetd.d/$rpcser | grep -i "disable" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "/etc/xinetd.d/$rpcser 파일에 disable = no로 설정되어 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "2" >> RPCservice.txt 2>&1
	fi
    done
else
	if [ -d /etc/xinetd.d 2> /dev/null ]
	then
		echo "/etc/xinetd.d 디렉터리에 RPC 서비스 관련 파일이 없음" >> $HOSTNAME.txt 2>&1
		echo "1" >> RPCservice.txt 2>&1
	else
		echo "/etc/xinetd.d 디렉터리가 존재하지 않음" >> $HOSTNAME.txt 2>&1
		echo "3" >> RPCservice.txt 2>&1
	fi
fi

echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/inetd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf 2> /dev/null ]
then
	cat /etc/inetd.conf | egrep $SERVICE_INETD >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -eq 0 ]
	then
		echo "/etc/inetd.conf 디렉터리에 RPC 서비스 관련 항목이 설정되지않아 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> RPCservice.txt 2>&1
	else
		echo "/etc/inetd.conf 디렉터리에 RPC 서비스 관련 항목이 설정되어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> RPCservice.txt 2>&1
	fi
else
    echo "/etc/inetd.conf 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo "3" >> RPCservice.txt 2>&1
fi

if [ `sort -u RPCservice.txt | grep "2" | wc -l` -ge 1 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-10] 취약 - SU3.10-불필요한 RPC 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
elif [ `sort -u RPCservice.txt | grep "3" | wc -l` -ge 1 ] ; then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-10] N/A - SU3.10-불필요한 RPC 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-10] 양호 - SU3.10-불필요한 RPC 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-10] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset SERVICE_INETD
rm RPCservice.txt


echo " [SU3-11]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "###################     SU3-11 불필요한 NIS, NIS+ 서비스를 비활성화 하고 있는가?    ####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"
ps -ef | egrep $SERVICE >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "NIS, NIS+ 서비스가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-11] 양호 - SU3.11-불필요한 NIS, NIS+ 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "NIS, NIS+ 서비스가 활성화되어있어 취약" >> $HOSTNAME.txt 2>&1
    echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-11] 취약 - SU3.11-불필요한 NIS, NIS+ 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-11] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset SERVICE


echo " [SU3-12]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "##################     SU3-12 불필요한 tftp, talk, ntalk 서비스를 비활성화 하고 있는가?    #################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ /etc/xinetd.d 확인 ]" >> $HOSTNAME.txt 2>&1
SERVICE_CHECK="tftp|talk|ntalk"

if [ `ls -alL /etc/xinetd.d 2> /dev/null | egrep $SERVICE_CHECK | wc -l` -gt 0 ]
then
    for service in `ls -alL /etc/xinetd.d | egrep $SERVICE_CHECK | grep -v "ssf" | awk '{print $9}'`
    do
	cat /etc/xinetd.d/$service | grep -i "disable" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `cat /etc/xinetd.d/$service | grep -i "disable" | awk -F= '{print $2}' | grep -i "yes" | wc -l` -eq 1 ]
	then
		echo "/etc/xinetd.d/$service 파일에 disable = yes로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> service.txt 2>&1
	else
		echo "/etc/xinetd.d/$service 파일에 disable = no로 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> service.txt 2>&1
	fi
    done
else
	echo " " >> $HOSTNAME.txt 2>&1
	if [ -d /etc/xinetd.d 2> /dev/null ]
	then
		echo "/etc/xinetd.d 디렉터리에 불필요한 tftp, talk, ntalk 서비스 관련 파일이 없음" >> $HOSTNAME.txt 2>&1
		echo "1" >> service.txt 2>&1
	else
		echo "/etc/xinetd.d 디렉터리가 존재하지 않음" >> $HOSTNAME.txt 2>&1
		echo "3" >> service.txt 2>&1
	fi
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/inetd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf 2> /dev/null ]
then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_CHECK >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_CHECK | wc -l` -eq 1 ]
	then
		echo "/etc/inetd.conf 디렉터리에 불필요한 tftp, talk, ntalk 서비스 관련 항목이 존재하지 않아 양호" >> $HOSTNAME.txt 2>&1
		echo "1" >> service.txt 2>&1
	else
		echo "/etc/inetd.conf 디렉터리에 불필요한 tftp, talk, ntalk 서비스 관련 항목이 설정되어있어 취약" >> $HOSTNAME.txt 2>&1
		echo "2" >> service.txt 2>&1
	fi
else
	echo " " >> $HOSTNAME.txt 2>&1
    echo "/etc/inetd.conf 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo "3" >> service.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ tftp(69), talk(517), ntalk(518) 포트 오픈 확인 ]" >> $HOSTNAME.txt 2>&1
netstat -na | grep :69 | grep udp >> $HOSTNAME.txt 2>&1
netstat -na | grep :517 | grep udp >> $HOSTNAME.txt 2>&1
netstat -na | grep :518 | grep udp >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -al | egrep ":tftp|:talk|:ntalk" | grep udp | wc -l` -eq 0 ]
then
	echo "불필요한 tftp, talk, ntalk 서비스 포트가 비활성화 되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo "1" >> service.txt 2>&1
else
	echo "불필요한 tftp, talk, ntalk 서비스 포트가 활성화 되어있어있어 취약" >> $HOSTNAME.txt 2>&1
	echo "2" >> service.txt 2>&1
fi

if [ `sort -u service.txt | grep "2" | wc -l` -ge 1 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-12] 취약 - SU3.12-불필요한 tftp, talk, ntalk 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-12] 양호 - SU3.12-불필요한 tftp, talk, ntalk 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-12] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset SERVICE_CHECK
rm service.txt


echo " [SU3-13]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#####################     SU3-13 Sendmail 최신버전의 패치가 적용되어 있는가?    ######################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ sendmail 프로세스 확인 ]" >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "Sendmail 서비스가 비활성화되어 있음" >> $HOSTNAME.txt 2>&1
	touch sendmail_tmp
else
	ps -ef | grep sendmail | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

if [ -f sendmail_tmp ]
then
	echo " " >> $HOSTNAME.txt 2>&1
else
	echo "[Sendmail 버전 확인]" >> $HOSTNAME.txt 2>&1
	if [ -f /etc/mail/sendmail.cf 2> /dev/null ]
	then
		grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/mail/sendmail.cf 파일 없음" >> $HOSTNAME.txt 2>&1
	fi
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ sendmail 설치여부 및 설정파일 확인 ]"   >> $HOSTNAME.txt 2>&1
rpm -qa sendmail 2> /dev/null >> $HOSTNAME.txt 2>&1
ls -al /etc/mail 2> /dev/null | grep "sendmail" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ postfix 메일서버 확인 ]" >> $HOSTNAME.txt 2>&1
rpm -qa postfix 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f sendmail_tmp ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-13] N/A - SU3.13-Sendmail 최신버전의 패치가 적용되어 있는가?" >> $HOSTNAME.txt 2>&1
elif [ `ps -ef | grep postfix | grep -v "grep" | wc -l` -ne 0 ]
then
	echo "sendmail을 사용하지 않고 postfix를 사용하고 있음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-13] N/A - SU3.13-Sendmail 최신버전의 패치가 적용되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[ CHECK]: sendmail 패치 버전 확인 후 최신 버전과 비교(2016년 1월 기준 최신버전 8.15.2 이상 권고)" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-13] 수동 - SU3.13-Sendmail 최신버전의 패치가 적용되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-13] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-14]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "####################     SU3-14 Sendmail 릴레이 제한 설정이 적절하게 되어있는가?    ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[ /etc/mail/access 확인]" >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ sendmail 서비스 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f sendmail_tmp ]
then
	echo " " >> $HOSTNAME.txt 2>&1
  	echo "Sendmail 서비스가 비활성화되어있음" >> $HOSTNAME.txt 2>&1
else
	if [ -f /etc/mail/access 2> /dev/null ]
	then
		echo "[ /etc/mail/access 확인 ]" >> $HOSTNAME.txt 2>&1
		cat /etc/mail/access >> $HOSTNAME.txt 2>&1
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "/etc/mail/access 파일이 없어 취약" >> $HOSTNAME.txt 2>&1
	fi
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/mail/sendmail.cf  확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/mail/sendmail.cf 2> /dev/null | grep "R$\*" | grep "Relaying denied" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/mail/access 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f sendmail_tmp ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "Sendmail 서비스가 비활성화되어있음" >> $HOSTNAME.txt 2>&1
  	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-14] N/A - SU3.14-Sendmail 릴레이 제한 설정이 적절하게 되어있는가?" >> $HOSTNAME.txt 2>&1
	echo "[SU3-14] End" >> $HOSTNAME.txt 2>&1
else
	if [ -f /etc/mail/access 2> /dev/null ]
	then
		if [ `cat /etc/mail/sendmail.cf 2> /dev/null | grep "DaemonPortOptions" | grep "0.0.0.0" | wc -l` -eq 0 ]
		then
			echo "[ CHECK] : SMTP 서비스가 비활성화되어 있거나, 릴레이 방지 설정을 한 경우 양호" >> $HOSTNAME.txt 2>&1
			echo "[ CHECK] : DaemonPortOptions 라인에 Addr 옵션이 없거나 0.0.0.0 설정되어 있으면 취약"  >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[ -------------------------------------------------- ]"  >> $HOSTNAME.txt 2>&1
			echo "[SU3-14] 스팸 메일 릴레이 제한 TIP"											>> $HOSTNAME.txt 2>&1
			echo "일부 relay를 풀어 주기 위해서 sendmail.cf를 변경하는 경우, spammer들의 표적이 되어  "		>> $HOSTNAME.txt 2>&1
			echo "다른 메일 서버로 부터 reject 당할 수 있으니 sendmail.cf를 변경하여 전체 relay를 풀면 안된다."	 >> $HOSTNAME.txt 2>&1
			echo "OK = [host에서지정된] 메일의 모든것을 허용[relay]한다. "									>> $HOSTNAME.txt 2>&1
			echo "RELAY = [host에서지정된]메일의 수신/발신을 허용한다."									>> $HOSTNAME.txt 2>&1
			echo "REJECT = [host에서지정된]메일의 수신/발신을 거부한다."									>> $HOSTNAME.txt 2>&1
			echo "DISCARD = /etc/sendmail.cf에 시정된 $#discard mailer에 지정된곳으로 메일을 폐기한다.(발신자는 메일 발신된것으로 알게됨)"  >> $HOSTNAME.txt 2>&1
			echo "501 <message> 지정된 user@host와 발신자의 주소가 전체 혹은 부분적으로 일치할 경우 이메일을 받지 않는다. "			 >> $HOSTNAME.txt 2>&1
			echo "553 <message> 발신자의 주소에 호스트명이 없을 경우 메일을 받지 않는다."							>> $HOSTNAME.txt 2>&1
			echo "550 <message> 지정된 도메인과 관련된 메일을 받지 않는다."									>> $HOSTNAME.txt 2>&1
			echo "보통 아주 간단한 예로서 111.111.111.111 이라는 pc에서 메일을 발송하기를 원한다면"					 >> $HOSTNAME.txt 2>&1
			echo "111.111.111.111		RELAY"												 >> $HOSTNAME.txt 2>&1
			echo "라는 한줄을 설정해 주는 것으로 메일을 발송을 할 수 있다."									 >> $HOSTNAME.txt 2>&1
			echo "ex1)	cyberspammer.com        REJECT"											 >> $HOSTNAME.txt 2>&1
			echo "ex2)	sendmail.org            OK"  			       							 >> $HOSTNAME.txt 2>&1
			echo "ex3)	128.32                  RELAY"											 >> $HOSTNAME.txt 2>&1
			echo "ex4)	localhost.localdomain   RELAY"											 >> $HOSTNAME.txt 2>&1
			echo "ex5)	localhost               RELAY"											 >> $HOSTNAME.txt 2>&1
			echo "ex6)	127.0.0.1               RELAY"											 >> $HOSTNAME.txt 2>&1
			echo "ex7)	linux.rootman.org       REJECT"                                 >> $HOSTNAME.txt 2>&1
			echo "ex8)	linux.rootman.org       501 Oh.. No.. linux.rootman.org"        >> $HOSTNAME.txt 2>&1
			echo "ex9)	linux.rootman.org       571 You are spammer.. "                 >> $HOSTNAME.txt 2>&1
			echo "/etc/mail/access에서 RELAY설정을 마친 후에는 access.db 를 갱신해 줘야 한다."      	  >> $HOSTNAME.txt 2>&1
			echo "makemap hash /etc/mail/access < /etc/mail/access"							 >> $HOSTNAME.txt 2>&1
			echo "라는 명령을 실행하여 갱신을 할 수 있다. "		   >> $HOSTNAME.txt 2>&1
			echo "access 파일을 수정 시 sendmail을 재시작 할 필요는 없으며 makemap을 이용하여 access.db 만 갱신해 주면 바로 적용이 된다." >> $HOSTNAME.txt 2>&1
			echo "DB에 정상적으로 저장되었는지 확인하는 명령어는 다음과 같다 strings access.db | grep 192"					 >> $HOSTNAME.txt 2>&1
			echo "strings access.db | grep 192"					 >> $HOSTNAME.txt 2>&1
			echo "[ -------------------------------------------------- ]"  >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-14] 수동 - SU3.14-Sendmail 릴레이 제한 설정이 적절하게 되어있는가?" >> $HOSTNAME.txt 2>&1
			echo "[SU3-14] End" >> $HOSTNAME.txt 2>&1
		else
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-14] 취약 - SU3.14-Sendmail 릴레이 제한 설정이 적절하게 되어있는가?" >> $HOSTNAME.txt 2>&1
			echo "[SU3-14] End" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/mail/access 파일이 없어 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-14] 취약 - SU3.14-Sendmail 릴레이 제한 설정이 적절하게 되어있는가?" >> $HOSTNAME.txt 2>&1
		echo "[SU3-14] End" >> $HOSTNAME.txt 2>&1
	fi
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-15]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "##############     SU3-15 일반 사용자의 Sendmail 실행 방지 설정이 적절하게 되어 있는가?    ################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
if [ -f sendmail_tmp ]
then
	echo " " >> $HOSTNAME.txt 2>&1
  	echo "Sendmail 서비스가 비활성화되어 있음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-15] N/A - SU3.15-일반 사용자의 Sendmail 실행 방지 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	echo "[SU3-15] End" >> $HOSTNAME.txt 2>&1
else
	echo "[ /etc/mail/sendmail.cf 확인 ]" >> $HOSTNAME.txt 2>&1
	if [ -f /etc/mail/sendmail.cf 2> /dev/null ]
	then
		cat /etc/mail/sendmail.cf 2> /dev/null | grep "O PrivacyOptions" >> $HOSTNAME.txt 2>&1
		if [ `cat /etc/mail/sendmail.cf 2> /dev/null | grep -v "^ *#" | grep "O PrivacyOptions" | grep restrictqrun | grep -v "grep" | wc -l ` -eq 0 ]
		then
			echo "/etc/mail/sendmail.cf 파일에 restrictqrun 설정이 존재하지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-15] 취약 - SU3.15-일반 사용자의 Sendmail 실행 방지 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
			echo "[SU3-15] End" >> $HOSTNAME.txt 2>&1
		else
			echo "/etc/mail/sendmail.cf 파일에 restrictqrun 설정이 존재하여 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-15] 양호 - SU3.15-일반 사용자의 Sendmail 실행 방지 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
			echo "[SU3-15] End" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/mail/sendmail.cf 파일 없음" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-15] 양호 - SU3.15-일반 사용자의 Sendmail 실행 방지 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		echo "[SU3-15] End" >> $HOSTNAME.txt 2>&1
	fi
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm sendmail_tmp 2> /dev/null


echo " [SU3-16]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#######################     SU3-16 DNS 최신버전의 보안패치가 적용되어 있는가?    ####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep named | grep -v grep | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "DNS 서비스가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-16] 양호 - SU3.16-DNS 최신버전의 보안패치가 적용되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[ DNS 서비스 사용 및 BIND 버전 확인 ]" >> $HOSTNAME.txt 2>&1
	ps -ef | grep named | grep -v grep >> $HOSTNAME.txt 2>&1
	named -v >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[ CHECK ]: 다음 이외의 BIND 버전을 사용하면 취약(8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-16] 수동 - SU3.16-DNS 최신버전의 보안패치가 적용되어 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-16] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-17]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#####################     SU3-17 DNS Zone Transfer 설정이 적절하게 되어 있는가?    ##################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "DNS 서비스가 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
    echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-17] 양호 - SU3.17-DNS Zone Transfer 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[ DNS 프로세스 확인 ]" >> $HOSTNAME.txt 2>&1
	ps -ef | grep named | grep -v "grep" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
    if [ -f /etc/named.conf 2>/dev/null -o -f /etc/bind/named.conf 2>/dev/null ]
	then
		echo "[ /etc/named.conf 파일 내 allow-transfer 확인 (BIND8)]" >> $HOSTNAME.txt 2>&1
		cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
        if [ `cat /etc/named.conf | grep "allow-transfer" | grep -w "0.0.0.0" | grep -v "^ *#" | wc -l` -eq 1 -o `cat /etc/bind/named.conf 2>/dev/null | grep "allow-transfer" | grep -w "0.0.0.0" | grep -v "^ *#" | wc -l` -eq 1 ]
        then
			echo "DNS Zone Transfer 설정이 모든 사용자에게 허용되어있어 취약" >> $HOSTNAME.txt 2>&1
            echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-17] 취약 - SU3.17-DNS Zone Transfer 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
        else
			echo "DNS Zone Transfer 설정이 허가된 사용자에게 허용되어있어 양호" >> $HOSTNAME.txt 2>&1
            echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-17] 양호 - SU3.17-DNS Zone Transfer 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
        fi
	elif [ -f /etc/named.boot 2>/dev/null ]
    then
		echo "[ /etc/named.boot 파일의 xfrnets 확인 (BIND4.9)]" >> $HOSTNAME.txt 2>&1
		cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
        if [ `cat /etc/named.boot 2>/dev/null | grep "xfrnets" | grep -w "0.0.0.0" | grep -v "^ *#" | wc -l` -eq 0 ]
        then
			echo "DNS Zone Transfer 설정이 모든 사용자에게 허용되어있어 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-17] 취약 - SU3.17-DNS Zone Transfer 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
        else
			echo "DNS Zone Transfer 설정이 허가된 사용자에게 허용되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-17] 양호 - SU3.17-DNS Zone Transfer 설정이 적절하게 되어 있는가?" *>> $HOSTNAME.txt 2>&1
        fi
    else
		echo "/etc/named.conf, /etc/named.boot 파일이 존재하지 않아 전송되는 정보 없음" >> $HOSTNAME.txt 2>&1
        echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-17] 양호 - SU3.17-DNS Zone Transfer 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
    fi
fi

echo "[SU3-17] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-18]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "######################     SU3-18 원격접속 시 SSH 서비스를 사용하고 있는가?    ######################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ Telnet 활성화 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep -v grep | grep telnet >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep 23 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ SSH 활성화 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep -v grep | grep ssh >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep 22 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -na | grep ":23 " | grep LISTEN | grep tcp | wc -l` -eq 0 ]
then
	echo "Telnet이 비활성화되어있어 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-18] 양호 - SU3.18-원격접속 시 SSH 서비스를 사용하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "Telnet이 활성화되어있어 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-18] 취약 - SU3.18-원격접속 시 SSH 서비스를 사용하고 있는가?" >> $HOSTNAME.txt 2>&11
fi

echo "[SU3-18] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-19]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "######################     SU3-19 불필요한 FTP 서비스를 비활성화 하고 있는가?    #####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ 21번포트 LISTEN 상태 확인 ]" >> $HOSTNAME.txt 2>&1
netstat -na | grep 21 | grep LISTEN | grep tcp >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 일반 FTP 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep "tftp" | grep -v "grep" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ ProFTP 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep "proftpd" | grep -v "grep" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ vsFTP 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep "vsftpd" | grep -v "grep" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `netstat -na | grep 21 | grep LISTEN | grep tcp | wc -l` -ne 0 2> /dev/null ]
then
	echo "FTP 서비스가 활성화 되어 있음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-19] 취약 - SU3.19-불필요한 FTP 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
elif [ `ps -ef | grep "ftp" | grep -v "grep" | wc -l` -ne 0 2> /dev/null ]
then
	echo "FTP 서비스가 활성화 되어 있음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-19] 취약 - SU3.19-불필요한 FTP 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "FTP 서비스가 비활성화 되어 있음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-19] 양호 - SU3.19-불필요한 FTP 서비스를 비활성화 하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-19] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-20]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "######################     SU3-20 FTP 계정에 shell이 적절하게 부여되어 있는가?    ####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ FTP 계정 확인 ]" >> $HOSTNAME.txt 2>&1

if [ `cat /etc/passwd | grep "ftp" | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "ftp 계정이 없으므로 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-20] 양호 - SU3.20-FTP 계정에 shell이 적절하게 부여되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	cat /etc/passwd | grep "ftp" | grep -v "grep" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	if [ `cat /etc/passwd | grep "ftp" | egrep "/bin/false|/sbin/nologin" | wc -l` -eq 0 ]
	then
		echo "ftp 계정의 shell이 /bin/false, /sbin/nologin이 아니므로 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-20] 취약 - SU3.20-FTP 계정에 shell이 적절하게 부여되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "ftp 계정 shell이 /bin/false, /sbin/nologin이므로 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-20] 양호 - SU3.20-FTP 계정에 shell이 적절하게 부여되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU3-20] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-21]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "################     SU3-21 Ftpuser 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?    #################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

filecount=0
permitCheck="...-.-----.*root.*"
etcPermitCheck="........wx.*root.*|..ws.....x.*root.*|.....ws..x.*root.*"

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ FTP 서비스 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep "tftp" | grep -v "grep" >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep "ftp" | grep -v "grep" | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "ftp가 비활성화되어 있음"  >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-21] N/A - SU3.21-Ftpuser 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[ ftpuser 파일 확인 ]" >> $HOSTNAME.txt 2>&1
	if [ -f /etc/ftpusers 2> /dev/null ]
	then
		echo "[ /etc/ftpusers 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/ftpusers | egrep $permitCheck | wc -l` -ne 0 ]
		then
			ls -al /etc/ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하이므로 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> ftp.txt 2>&1
		else
			ls -al /etc/ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하가 아니므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> ftp.txt 2>&1
		fi
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/ftpd/ftpusers 2> /dev/null ]
	then
		echo "[ /etc/ftpd/ftpusers 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/ftpd/ftpusers | egrep $permitCheck | wc -l` -ne 0 ]
		then
			ls -al /etc/ftpd/ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하이므로 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> ftp.txt 2>&1
		else
			ls -al /etc/ftpd/ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하가 아니므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> ftp.txt 2>&1
		fi
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd/ftpusers 2> /dev/null ]
	then
		echo "[ /etc/vsftpd/ftpusers 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/vsftpd/ftpusers | egrep $permitCheck | wc -l` -ne 0 ]
		then
			ls -al /etc/vsftpd/ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하이므로 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> ftp.txt 2>&1
		else
			ls -al /etc/vsftpd/ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하가 아니므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> ftp.txt 2>&1
		fi
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd/vsftpd.ftpusers 2> /dev/null ]
	then
		echo "[ /etc/vsftpd.ftpusers 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/vsftpd.ftpusers | egrep $permitCheck | wc -l` -ne 0 ]
		then
			ls -al /etc/vsftpd.ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하이므로 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> ftp.txt 2>&1
		else
			ls -al /etc/vsftpd.ftpusers >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하가 아니므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> ftp.txt 2>&1
		fi
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd/user_list 2> /dev/null ]
	then
		echo "[ /etc/vsftpd/user_list 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/vsftpd/user_list | egrep $permitCheck | wc -l` -ne 0 ]
		then
			ls -al /etc/vsftpd/user_list >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하이므로 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> ftp.txt 2>&1
		else
			ls -al /etc/vsftpd/user_list >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하가 아니므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> ftp.txt 2>&1
		fi
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd.user_list 2> /dev/null ]
	then
		echo "[ /etc/vsftpd.user_list 확인 ]" >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/vsftpd.user_list | egrep $permitCheck | wc -l` -ne 0 ]
		then
			ls -al /etc/vsftpd.user_list >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하이므로 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> ftp.txt 2>&1
		else
			ls -al /etc/vsftpd.user_list >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "소유자 root, 권한 640 이하가 아니므로 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> ftp.txt 2>&1
		fi
	else
		filecount=$(($filecount+1))
	fi

	if [ $filecount -eq 6 ]
	then
		if [ `ls -alL / | grep -w "etc" | egrep $etcPermitCheck | wc -l` -eq 0 -a `ls -alL /etc | grep -w "ftpd" | egrep $etcPermitCheck | wc -l` -eq 0 -a `ls -alL /etc | grep -w "vsftpd" | egrep $etcPermitCheck | wc -l` -eq 0 ]
		then
			echo "ftpuser 파일이 없지만, Other 권한으로 해당 파일 생성 및 수정이 불가하여 양호" >> $HOSTNAME.txt 2>&1
			ls -alL / | grep etc 2> /dev/null >> $HOSTNAME.txt 2>&1
			ls -alL /etc | grep ftpd 2> /dev/null >> $HOSTNAME.txt 2>&1
			ls -alL /etc | grep vsftpd 2> /dev/null >> $HOSTNAME.txt 2>&1
			echo "1" >> ftp.txt 2>&1
		fi
	else
		echo "ftpuser 파일이 없고, Other 권한으로 해당 파일 생성 및 수정이 가능하여 취약" >> $HOSTNAME.txt 2>&1
		ls -alL / | grep etc 2> /dev/null >> $HOSTNAME.txt 2>&1
		ls -alL /etc | grep ftpd 2> /dev/null >> $HOSTNAME.txt 2>&1
		ls -alL /etc | grep vsftpd 2> /dev/null >> $HOSTNAME.txt 2>&1
		echo "2" >> ftp.txt 2>&1
	fi
fi

if [ -f ftp.txt 2> /dev/null ]
then
	if [ `sort -u ftp.txt | grep "2" | wc -l` -ge 1 ]
	then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-21] 취약 - SU3.21-Ftpuser 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-21] 양호 - SU3.21-Ftpuser 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU3-21] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm ftp.txt 2>/dev/null
unset filecount
unset permitCheck
unset etcPermitCheck


echo " [SU3-22]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "########################     SU3-22 FTP 접속 시 root 접속을 제한하고 있는가?    ######################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

filecount=0
echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep "ftp" | grep -v "grep" | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "ftp가 비활성화되어 있음"  >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-22] N/A - SU3.22-FTP 접속 시 root 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[ ftpuser 파일 확인 ]" >> $HOSTNAME.txt 2>&1
	if [ -f /etc/ftpuser 2> /dev/null ]
	then
		echo "[ /etc/ftpusers 확인 ]" >> $HOSTNAME.txt 2>&1
		cat /etc/ftpusers >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/ftpuser"
		echo "1" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/ftpd/ftpusers 2> /dev/null ]
	then
		echo "[ /etc/ftpd/ftpusers 확인]" >> $HOSTNAME.txt 2>&1
		cat /etc/ftpd/ftpusers >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/ftpd/ftpusers"
		echo "1" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd/ftpusers 2> /dev/null ]
	then
		echo "[ /etc/vsftpd/ftpusers 확인]" >> $HOSTNAME.txt 2>&1
		cat /etc/vsftpd/ftpusers >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/vsftpd/ftpusers"
		echo "1" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd.ftpusers 2> /dev/null ]
	then
		echo "[ /etc/vsftpd.ftpusers 확인]" >> $HOSTNAME.txt 2>&1
		cat /etc/vsftpd.ftpusers >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/vsftpd.ftpusers"
		echo "1" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd/user_list 2> /dev/null ]
	then
		echo "[ /etc/vsftpd/user_list 확인]" >> $HOSTNAME.txt 2>&1
		cat /etc/vsftpd/user_list >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/vsftpd/user_list"
		echo "1" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/vsftpd.user_list 2> /dev/null ]
	then
		echo "[ /etc/vsftpd.user_list 확인]" >> $HOSTNAME.txt 2>&1
		cat /etc/vsftpd.user_list >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/vsftpd.user_list"
		echo "1" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/proftpd.conf 2> /dev/null ]
	then
		echo "[ /etc/proftpd.conf 확인]" >> $HOSTNAME.txt 2>&1
		cat /etc/proftpd.conf | grep -i "rootlogin" >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/proftpd.conf"
		echo "2" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ -f /etc/proftpd/proftpd.conf 2> /dev/null ]
	then
		echo "[ /etc/proftpd/proftpd.conf 확인]" >> $HOSTNAME.txt 2>&1
		cat /etc/proftpd/proftpd.conf | grep -i "rootlogin" >> $HOSTNAME.txt 2>&1
		FTPUSER="/etc/proftpd/proftpd.conf"
		echo "2" >> ftp_root.txt 2>&1
	else
		filecount=$(($filecount+1))
	fi

	if [ $filecount -eq 8 ]
	then
		echo "ftpuser 파일이 검색되지않아 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-22] 양호 - SU3.22-FTP 접속 시 root 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

if [ -f ftp.txt 2> /dev/null ]
then
	if [ `sort -u ftp_root.txt 2>/dev/null | grep "1" | wc -l` -eq 1 ]
	then
		if  [ `cat $FTPUSER | grep -i "root" | grep "^#" | wc -l` -eq 1 -o `cat $FTPUSER 2>/dev/null | grep -i "root" | wc -l` -eq 0 ]
		then
			echo "ftpuser 파일에 root에 주석 처리가 되어있거나, root 계정이 미등록 되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-22] 양호 - SU3.22-FTP 접속 시 root 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "ftpuser 파일에 root 계정이 등록 되어있어 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-22] 취약 - SU3.22-FTP 접속 시 root 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	else
		if [`cat $FTPUSER | grep -i "rootlogin" | grep -i "off" | wc -l` -eq 1 ]
		then
			echo "ftpuser 파일에 RootLogin off로 설정되어 있는 경우 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-22] 양호 - SU3.22-FTP 접속 시 root 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "ftpuser 파일에 RootLogin on으로 설정되어 있는 경우 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-22] 취약 - SU3.22-FTP 접속 시 root 접속을 제한하고 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	fi
fi


echo "[SU3-22] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
rm ftp_root.txt 2>/dev/null
unset FTPUSER


echo " [SU3-23]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "################     SU3-23 at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?    ###############"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ at.allow/deny 파일 소유자 및 권한 확인 ]" >> $HOSTNAME.txt 2>&1
ls -lL /etc/at* 2> /dev/null >> $HOSTNAME.txt 2>&1
ls -lL /etc/cron.d/at* 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

permitCheck="...-.-----.*root.*|...-.-----.*bin.*"
etcPermitCheck="........wx.*root.*|..ws.....x.*root.*|.....ws..x.*root.*"

if [ -f /etc/at.allow 2> /dev/null -a -f /etc/at.deny 2> /dev/null ]
then
	if [ `ls -alL /etc/at.allow | egrep $permitCheck | wc -l` -eq 0 -o `ls -alL /etc/at.deny | egrep $permitCheck | wc -l` -eq 0 ]
	then
		echo "/etc/at.allow와 /etc/at.deny가 소유자가 root이고, 권한이 640 이하로 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 취약 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/at.allow와 /etc/at.deny가 소유자가 root이고, 권한이 640 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 양호 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
elif [ -f /etc/at.allow 2> /dev/null ]
then
	if [ `ls -alL /etc/at.allow | egrep $permitCheck | wc -l` -eq 0 ]
	then
		echo "/etc/at.allow가 소유자가 root이고, 권한이 640 이하로 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 취약 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/at.allow가 소유자가 root이고, 권한이 640 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 양호 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
elif [ -f /etc/at.deny 2> /dev/null ]
then
	if [ `ls -alL /etc/at.deny | egrep $permitCheck | wc -l` -eq 0 ]
	then
		echo "/etc/at.deny가 소유자가 root이고, 권한이 640 이하로 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 취약 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/at.deny가 소유자가 root이고, 권한이 640 이하로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 양호 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
else
	if [ `ls -alL / | grep -w "etc" | egrep $etcPermitCheck | wc -l` -eq 0 ]
	then
		ls -alL / | grep etc >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "/etc/at.* 파일이 없지만, Other 권한으로 해당 파일 생성 및 수정이 불가하여 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 양호 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	else
		ls -alL / | grep etc >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "/etc/at.*파일이 없고, Other 권한으로 해당 파일 생성 및 수정이 가능하여 취약" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-23] 취약 - SU3.23-at 접근제어 파일의 소유자 및 권한 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU3-23] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-24]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#######################     SU3-24 불필요한 SNMP 서비스를 비활성화하고 있는가?    ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ SNMP 서비스 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep snmp | grep -v "grep" >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "SNMP 비활성화되어있어 양호" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-24] 양호 - SU3.24-불필요한 SNMP 서비스를 비활성화하고 있는가?" >> $HOSTNAME.txt 2>&1
	touch snmp_tmp
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "SNMP 활성화되어있어 취약" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-24] 취약 - SU3.24-불필요한 SNMP 서비스를 비활성화하고 있는가?" >> $HOSTNAME.txt 2>&1
fi

echo "[SU3-24] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-25]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#################     SU3-25 SNMP Community String 설정이 적절하게 되어 있는가?    #################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
SNMP_COUNT=0

if [ -f snmp_tmp ]
then
	rm snmp_tmp
	echo " " >> $HOSTNAME.txt 2>&1
	echo "SNMP 비활성화되어 있음"  >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-25] N/A  - SU3.25-SNMP Community String 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	echo "[ SNMP Community String 설정 파일 확인 ]" >> $HOSTNAME.txt 2>&1
	if [ -f /etc/snmpd.conf 2> /dev/null ]
	then
		echo "[ /etc/snmpd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
		cat /etc/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		if [ `cat /etc/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' | wc -l` -eq 0 ]
		then
			echo "SNMP Community 이름이 public, private가 설정되지않아 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> SNMP.txt 2>&1
		else
			echo "SNMP Community 이름이 public, private로 설정되어 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> SNMP.txt 2>&1
		fi
	else
		SNMP_COUNT=$(($SNMP_COUNT+1))
	fi

	if [ -f /etc/snmp/snmpd.conf 2> /dev/null ]
	then
		echo "[ /etc/snmp/snmpd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
		cat /etc/snmp/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
		if [ `cat /etc/snmp/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' | wc -l` -eq 0 ]
		then
			echo "SNMP Community 이름이 public, private로 설정되어있지않아 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> SNMP.txt 2>&1
		else
			echo "SNMP Community 이름이 public, private로 설정되어 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> SNMP.txt 2>&1
		fi
	else
		SNMP_COUNT=$(($SNMP_COUNT+1))
	fi

	if [ -f /etc/snmp/conf/snmpd.conf 2> /dev/null ]
	then
		echo "[ /etc/snmp/conf/snmpd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
		cat /etc/snmp/conf/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
		if [ `cat /etc/snmp/conf/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' | wc -l` -eq 0 ]
		then
			echo "SNMP Community 이름이 public, private가 설정되어있지않아 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> SNMP.txt 2>&1
		else
			echo "SNMP Community 이름이 public, private로 설정되어 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> SNMP.txt 2>&1
		fi
	else
		SNMP_COUNT=$(($SNMP_COUNT+1))
	fi

	if [ -f /usr/local/share/snmp/snmpd.conf 2> /dev/null ]
	then
		echo "[ /usr/local/share/snmp/snmpd.conf 확인 ]" >> $HOSTNAME.txt 2>&1
		cat /usr/local/share/snmp/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
		if [ `cat /usr/local/share/snmp/snmpd.conf | egrep -i ' *public| *private' | grep -v "^ *#" | egrep -v 'group|trap' | wc -l` -eq 0 ]
		then
			echo "SNMP Community 이름이 public, private가 설정되어있지않아 양호" >> $HOSTNAME.txt 2>&1
			echo "1" >> SNMP.txt 2>&1
		else
			echo "SNMP Community 이름이 public, private로 설정되어 취약" >> $HOSTNAME.txt 2>&1
			echo "2" >> SNMP.txt 2>&1
		fi
	else
		SNMP_COUNT=$(($SNMP_COUNT+1))
	fi

	if [ $SNMP_COUNT -eq 4 ]
	then
		echo "SNMP Community String 설정 파일이 존재하지 않음"
		echo "3" >> SNMP.txt 2>&11
	fi
fi

if [ -f SNMP.txt ]
then
	if [ `sort -u SNMP.txt 2> /dev/null | grep "2" | wc -l` -ge 1 ]
	then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-25] 취약 - SU3.25-SNMP Community String 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		rm SNMP.txt
	elif [ `sort -u SNMP.txt | grep "3" | wc -l` -eq 1 ] ; then
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-25] N/A - SU3.25-SNMP Community String 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		rm SNMP.txt
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-25] 양호 - SU3.25-SNMP Community String 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		rm SNMP.txt
	fi
fi

echo "[SU3-25] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
unset SNMP_COUNT


echo " [SU3-26]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "########################     SU3-26 로그온 시 배너설정이 적절하게 되어 있는가?    #####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 1. issue.net && motd 파일의 내용이 기본 설정이거나 경고메시지가 없을 경우 취약" >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 2. telnet 서비스가 중지되어 있을 경우 /etc/issue.net 설정 고려하지 않아도 됨" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/motd 확인]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/motd 2> /dev/null ]
then
	cat /etc/motd 2> /dev/null >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "/etc/motd가 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/issue.net 확인]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/issue.net 2> /dev/null ]
then
	cat /etc/issue.net 2> /dev/null >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "/etc/issue.net이 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/issue.net 확인]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/issue.net 2> /dev/null ]
then
	cat /etc/issue.net 2> /dev/null >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "/etc/issue.net이 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/ssh/sshd_config 확인" >> $HOSTNAME.txt 2>&1
if [ -f /etc/ssh/sshd_config 2> /dev/null ]
then
	cat /etc/ssh/sshd_config 2> /dev/null | grep -i "banner" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "/etc/ssh/sshd_config가 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/mail/sendmail.cf 확인" >> $HOSTNAME.txt 2>&1
if [ -f /etc/mail/sendmail.cf 2> /dev/null ]
then
	cat /etc/mail/sendmail.cf 2> /dev/null | grep -v "^ *#" | grep -i "O Smtp GreetingMessage" >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "/etc/mail/sendmail.cf가 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/named.conf 확인" >> $HOSTNAME.txt 2>&1
if [ -f /etc/named.conf 2> /dev/null ]
then
	cat /etc/named.conf 2> /dev/null >> $HOSTNAME.txt 2>&1
else
	echo " " >> $HOSTNAME.txt 2>&1
	echo "/etc/named.conf가 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ ----------------------------------------------------------------- ]" 	>> $HOSTNAME.txt 2>&1
echo "  [SU3-26] 로그온 시 경고 메시지 제공 TIP! "					   					>> $HOSTNAME.txt 2>&1
echo "  경고메세지 설정은 다음과 같은 파일에서 처리한다."	     									>> $HOSTNAME.txt 2>&1
echo "  issue.net = 사용자가 로그인전에 출력되는 메세지 [ssh는 별도설정필요]"						>> $HOSTNAME.txt 2>&1
echo "  motd = 사용자가 로그인후에 출력되는메세지 "             								>> $HOSTNAME.txt 2>&1
echo "  ssh를 사용한다면 /etc/ssh/sshd_config 파일 내 #Banner none 구문의 주석을 제거한 후"		>> $HOSTNAME.txt 2>&1
echo "  ex1) #Banner none 에서 Banner /etc/issue.net으로 베너 경로를"					>> $HOSTNAME.txt 2>&1
echo "  변경하여야만 ssh로 로그인 시 베너가 출력된다."											>> $HOSTNAME.txt 2>&1
echo "  단, motd 파일은 접속후에 메세지를 출력하기때문에 별도의 설정없이 telnet 및 ssh 모두 메세지가 출력된다."	>> $HOSTNAME.txt 2>&1
echo "  정보통신기반시설 가이드라인 기준은 SSH 배너 설정부분은 언급되지 않으므로, "						>> $HOSTNAME.txt 2>&1
echo "  설정되지않아도 양호 처리하나, 여력이 될 시 권고사항으로 언급."									>> $HOSTNAME.txt 2>&1
echo "[ ----------------------------------------------------------------- ]"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[SU3-26] 수동 - SU3.26-로그온 시 배너설정이 적절하게 되어 있는가? " >> $HOSTNAME.txt 2>&1
echo "[SU3-26] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-27]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "##################     SU3-27 NFS 설정파일의 소유자 및 권한이 적절하게 되어 있는가?    ##################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

permitCheck="...-.--.--.*root.*"
etcPermitCheck="........wx.*root.*|..ws.....x.*root.*|.....ws..x.*root.*"

if [ `ps -ef | egrep "nfs" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "NFS 서비스가 비활성화 되어 있음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-27] N/A - SU3.27-NFS 설정파일의 소유자 및 권한이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
else
	if [ -f /etc/exports 2> /dev/null ]
	then
		echo "[ /etc/exports 소유자 및 권한 확인]" >> $HOSTNAME.txt 2>&1
		ls -alL /etc/exports >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/exports | egrep $permitCheck | wc -l` -eq 0 ]
		then
			echo "/etc/exports의 소유자가 root이거나, 권한이 644 이하의 권한으로 설정되어있지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-27] 취약 - SU3.27-NFS 설정파일의 소유자 및 권한이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "/etc/exports의 소유자가 root이거나, 권한이 644 이하의 권한으로 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-27] 양호 - SU3.27-NFS 설정파일의 소유자 및 권한이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	else
		ls -alL / | grep etc >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		if [ `ls -alL / | grep -w "etc" | egrep $etcPermitCheck | wc -l` -eq 0 ]
		then
			echo "/etc/exports 파일이 없지만, Other 권한으로 해당 파일 생성 및 수정이 불가하여 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-27] 양호 - SU3.27-NFS 설정파일의 소유자 및 권한이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		else
			echo "/etc/exports 파일이 없고, Other 권한으로 해당 파일 생성 및 수정이 가능하여 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-27] 취약 - SU3.27-NFS 설정파일의 소유자 및 권한이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	fi
fi

echo "[SU3-27] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU3-28]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "####################     SU3-28 expn, novrfy 옵션 설정이 적절하게 되어 있는가?    #####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

if [ -f sendmail_tmp ]
then
	echo " " >> $HOSTNAME.txt 2>&1
	echo "Sendmail 서비스 비활성화 되어있음" >> $HOSTNAME.txt 2>&1
	echo " " >> $HOSTNAME.txt 2>&1
	echo "[SU3-28] N/A - SU3.28-expn, novrfy 옵션 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	rm sendmail_tmp
else
	echo "[ /etc/mail/sendmail.cf 옵션 확인 ]" >> $HOSTNAME.txt 2>&1
	if [ -f /etc/mail/sendmail.cf 2> /dev/null ]
	then
	    if [ `cat /etc/mail/sendmail.cf | grep -v "^ *#" | grep "O PrivacyOptions" | grep authwarnings | grep novrfy | grep noexpn | grep -v "grep" | wc -l ` -ne 0 ]
		then
			cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|novrfy|noexpn" | grep -v "grep" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "/etc/mail/sendmail.cf에 noexpn, novrfy 옵션이 설정되어있어 양호" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-28] 양호 - SU3.28-expn, novrfy 옵션 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		else
			cat /etc/mail/sendmail.cf 2> /dev/null | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|novrfy|noexpn|goaway" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "/etc/mail/sendmail.cf에 noexpn, novrfy 옵션이 설정되지않아 취약" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			echo "[SU3-28] 취약 - SU3.28-expn, novrfy 옵션 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/mail/sendmail.cf 파일이 존재하지않아 양호" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "[SU3-28] 양호 - SU3.28-expn, novrfy 옵션 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
	fi
fi

echo "[SU3-28] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "################### 4. System Version Management ###################"
echo "################### 4. 패치 관리 ###################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " [SU4-01]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "####################     SU4-01 OS, 서비스의 최신 보안패치가 적용되어 있는가?     #####################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1
echo "[ CHECK ]: 수동 진단 - 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있는 경우 양호 " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[ 모든 시스템 정보 확인 ]" >> $HOSTNAME.txt 2>&1
uname -a >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 커널 Release 번호 확인 ]"          >> $HOSTNAME.txt 2>&1
uname -r          >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 커널 버전 확인 ]" >> $HOSTNAME.txt 2>&1
cat /proc/version 2> /dev/null  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ OS 정보 확인 ]" >> $HOSTNAME.txt 2>&1
cat /etc/*release 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 서비스 버전은 systeminfo 파일 참고 ]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME-SystemInformation.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[SU4-01] 수동 - SU4.01-OS, 서비스의 최신 보안패치가 적용되어 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU4-01] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "################### 5. System Log Management ###################"
echo "################### 5. 로그 관리 ###################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " [SU5-01]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "#####################     SU5-01 정기적으로 로그 검토 및 보고가 이루어지고 있는가?     ###################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

echo "[ CHECK]: 1. 로그 기록의 검토, 분석, 리포트 작성 및 보고 등이 정기적으로 이루어지는 경우 양호 " >> $HOSTNAME.txt 2>&1
echo "[ CHECK]: 2. ISMS/ISO27001 통제항목 Interview 결과 참고" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[SU5-01] 수동 - SU5.01-정기적으로 로그 검토 및 보고가 이루어지고 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU5-01] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " [SU5-02]  Checking..."
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "################     SU5-02 로그 기록 정책에 따른 syslog 설정이 적절하게 되어 있는가?     ##################"  >> $HOSTNAME.txt 2>&1
echo "#######################################################################################"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "---------------------------- 현  황 ----------------------------" >> $HOSTNAME.txt 2>&1

echo "[ CHECK] : 1. 로그 기록 정책에 따라 syslog.conf 파일이 설정되어있으면 양호 " >> $HOSTNAME.txt 2>&1
echo "[ CHECK] : 2. 로그 파일의 권한 중 Other에 쓰기 권한이 부여되어 있는지 확인 필요" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ syslog 프로세스 확인 ]" >> $HOSTNAME.txt 2>&1
ps -ef | grep 'syslog' | grep -v grep >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/syslog.conf 확인 ]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/syslog.conf 2> /dev/null]
then
	cat /etc/syslog.conf 2> /dev/null >> $HOSTNAME.txt 2>&1
else
	echo "/etc/syslog.conf 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ /etc/rsyslog.conf 설정 ]" >> $HOSTNAME.txt 2>&1
if [ -f /etc/rsyslog.conf 2> /dev/null]
then
	cat /etc/rsyslog.conf 2> /dev/null >> $HOSTNAME.txt 2>&1
else
	echo "/etc/rsyslog.conf 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "[ 로그파일 권한 확인 ]" >> $HOSTNAME.txt 2>&1
LOGFILES="/var/log/wtmpx /var/log/utmpx /var/log/wtmp /var/log/utmp /var/wtmp /var/run/utmp /var/utmp /var/log/btmp /var/log/pacct /var/log/messages /var/log/lastlog /var/log/secure /var/log/sulog"

for file in $LOGFILES
	do
	if [ -f $file ]
	then
		ls -al $file >> $HOSTNAME.txt 2>&1
	fi
	done
echo "++++++ Other에 쓰기 권한이 있는지 Check ++++++" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "[ -------------------------------------------------- ]"  >> $HOSTNAME.txt 2>&1
echo "[SU5-02] 정책에 따른 시스템 로깅 설정 TIP" >> $HOSTNAME.txt 2>&1
echo "최신버전의 LINUX는 /etc/syslog.conf가 아닌 /etc/rsyslog.conf 를 사용한다." >> $HOSTNAME.txt 2>&1
echo "기 구축장비가 아닌 신규사업시 대부분 CentOS[무료], 상위버전 및 REDHAT[유료] 상위버전이 설치됨으로 유의해야 한다." >> $HOSTNAME.txt 2>&1
echo "또한, 주요정보통신기반시설 가이드라인 기준에는 로그파일 접근권한에 대해서 언급이 없지만, " >> $HOSTNAME.txt 2>&1
echo "보안 상 로그파일은 Other에 쓰기 권한을 제거를 권고해야 한다." >> $HOSTNAME.txt 2>&1
echo "[ -------------------------------------------------- ]"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[SU5-02] 수동 - SU5.02-로그 기록 정책에 따른 syslog 설정이 적절하게 되어 있는가?" >> $HOSTNAME.txt 2>&1
echo "[SU5-02] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

clear
echo "################### END #####################"
echo "################### END #####################"
echo "################ 수고하셨습니다  ##################"
echo "################### END #####################"  >> $HOSTNAME.txt 2>&1
echo "################### END #####################"  >> $HOSTNAME.txt 2>&1
echo "################ 수고하셨습니다  ##################"  >> $HOSTNAME.txt 2>&1

mv $HOSTNAME.txt "temp_"$HOSTNAME".txt"
sed 's/$'"/`echo \\\r`/" temp_$HOSTNAME.txt > $HOSTNAME.txt
rm -rf temp_$HOSTNAME.txt

mv $HOSTNAME-SystemInformation.txt "temp_"$HOSTNAME-SystemInformation".txt"
sed 's/$'"/`echo \\\r`/" temp_$HOSTNAME-SystemInformation.txt > $HOSTNAME-SystemInformation.txt
rm -rf temp_$HOSTNAME-SystemInformation.txt